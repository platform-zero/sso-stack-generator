@file:OptIn(kotlin.io.path.ExperimentalPathApi::class)

import com.fasterxml.jackson.core.JsonGenerator
import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.SerializationFeature
import com.fasterxml.jackson.databind.node.ArrayNode
import com.fasterxml.jackson.databind.node.JsonNodeFactory
import com.fasterxml.jackson.databind.node.ObjectNode
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.security.MessageDigest
import kotlin.io.path.*

val json = ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT)
val yaml = ObjectMapper(YAMLFactory().disable(JsonGenerator.Feature.AUTO_CLOSE_TARGET))
    .enable(SerializationFeature.INDENT_OUTPUT)
val nodes = JsonNodeFactory.instance

fun fail(message: String): Nothing = error("stack generator: $message")
fun obj(): ObjectNode = nodes.objectNode()
fun arr(): ArrayNode = nodes.arrayNode()
fun JsonNode.fieldsMap(): List<Pair<String, JsonNode>> = fields().asSequence().map { it.key to it.value }.toList()
fun JsonNode.textOrNull(): String? = takeUnless { isNull || isMissingNode }?.asText()

fun parseArgs(raw: Array<String>): Pair<String, Map<String, String>> {
    val values = linkedMapOf<String, String>()
    var command = "generate"
    var index = 0
    if (raw.isNotEmpty() && !raw[0].startsWith("-")) {
        command = raw[0]
        index = 1
    }
    while (index < raw.size) {
        val key = raw[index]
        if (!key.startsWith("--") || index + 1 >= raw.size) fail("expected --name value, got '$key'")
        values[key.removePrefix("--")] = raw[index + 1]
        index += 2
    }
    return command to values
}

fun required(options: Map<String, String>, name: String): String =
    options[name] ?: fail("missing --$name")

fun readTree(path: Path): ObjectNode {
    if (!path.isRegularFile()) fail("missing file: $path")
    val mapper = if (path.extension in setOf("yaml", "yml")) yaml else json
    val value = mapper.readTree(path.toFile())
    if (value !is ObjectNode) fail("expected an object in $path")
    return value
}

fun writeYaml(path: Path, value: JsonNode) {
    path.parent?.createDirectories()
    yaml.writeValue(path.toFile(), value)
}

fun writeJson(path: Path, value: JsonNode) {
    path.parent?.createDirectories()
    json.writeValue(path.toFile(), value)
}

fun copyField(source: ObjectNode, target: ObjectNode, sourceName: String, targetName: String = sourceName) {
    source.get(sourceName)?.let { target.set<JsonNode>(targetName, it.deepCopy()) }
}

fun lifecycle(service: ObjectNode): String {
    if (service.path("x-webservices-on-demand").asBoolean(false)) return "on-demand"
    return if (service.path("restart").asText("no") == "no") "oneshot" else "daemon"
}

fun dependencyCondition(value: JsonNode): String {
    val condition = if (value.isTextual) "service_started" else value.path("condition").asText("service_started")
    return when (condition) {
        "service_started" -> "started"
        "service_healthy" -> "healthy"
        "service_completed_successfully" -> "completed"
        else -> fail("unsupported dependency condition: $condition")
    }
}

fun importService(name: String, source: ObjectNode): ObjectNode {
    val service = obj()
    copyField(source, service, "image")
    source.get("build")?.let { buildNode ->
        val build = if (buildNode.isTextual) obj().put("context", buildNode.asText()) else buildNode.deepCopy<ObjectNode>()
        build.remove("args")?.let { build.set<JsonNode>("arguments", it) }
        build.remove("dockerfile")?.let { build.set<JsonNode>("containerfile", it) }
        service.set<ObjectNode>("build", build)
    }
    copyField(source, service, "container_name", "containerName")
    val serviceLifecycle = lifecycle(source)
    service.put("lifecycle", serviceLifecycle)
    val image = source.path("image").asText("")
    val localImage = image.startsWith("stack/") || image.startsWith("webservices/") || image.startsWith("webservices-")
    service.put("updatePolicy", if (serviceLifecycle == "daemon" && image.isNotBlank() && !localImage && image.substringBefore('@').contains(':')) "registry" else "pinned")
    service.put("placement", "rootful")

    source.get("depends_on")?.let { dependenciesNode ->
        val dependencies = obj()
        if (dependenciesNode.isArray) dependenciesNode.forEach { dependencies.put(it.asText(), "started") }
        else dependenciesNode.fieldsMap().forEach { (dependency, condition) -> dependencies.put(dependency, dependencyCondition(condition)) }
        service.set<ObjectNode>("dependencies", dependencies)
    }

    listOf(
        "environment" to "environment", "networks" to "networks", "volumes" to "volumes",
        "ports" to "ports", "healthcheck" to "health", "command" to "command",
        "entrypoint" to "entrypoint", "restart" to "restart", "working_dir" to "workingDir",
        "user" to "user", "hostname" to "hostname", "dns" to "dns", "extra_hosts" to "extraHosts",
        "tmpfs" to "tmpfs", "read_only" to "readOnly", "init" to "init", "cap_add" to "capAdd",
        "cap_drop" to "capDrop", "security_opt" to "securityOpt", "sysctls" to "sysctls",
        "ulimits" to "ulimits", "shm_size" to "shmSize", "stop_grace_period" to "stopGracePeriod",
        "userns_mode" to "userns", "group_add" to "groupAdd"
    ).forEach { (from, to) -> copyField(source, service, from, to) }
    source.path("deploy").path("resources").takeUnless { it.isMissingNode }?.let {
        service.set<JsonNode>("resources", it.deepCopy())
    }
    return service
}

fun mergeRuntimeOverlayFile(runtime: ObjectNode, path: Path) {
    val runtimeOverlay = readTree(path)
    val anchors = Regex("(?m)^([A-Za-z0-9_.-]+):\\s*&([A-Za-z0-9_.-]+)\\s*$")
        .findAll(path.readText())
        .mapNotNull { match -> runtimeOverlay.get(match.groupValues[1])?.let { match.groupValues[2] to it } }
        .toMap()
    val services = runtime.with("services")
    runtimeOverlay.path("services").fieldsMap().forEach { (name, value) ->
        if (services.has(name)) fail("duplicate service '$name' while importing $path")
        val raw = value as ObjectNode
        val resolved = obj()
        raw.get("<<")?.let { inherited ->
            val inheritedObject = when {
                inherited.isObject -> inherited
                inherited.isTextual -> anchors[inherited.asText()]
                else -> null
            } ?: fail("unsupported YAML merge for service '$name' in $path: $inherited")
            inheritedObject.fieldsMap().forEach { (key, inheritedValue) -> resolved.set<JsonNode>(key, inheritedValue.deepCopy()) }
        }
        raw.fieldsMap().filterNot { it.first == "<<" }.forEach { (key, ownValue) -> resolved.set<JsonNode>(key, ownValue.deepCopy()) }
        services.set<ObjectNode>(name, importService(name, resolved))
    }
    val networks = runtime.with("networks")
    runtimeOverlay.path("networks").fieldsMap().forEach { (name, value) ->
        if (!networks.has(name)) {
            val network = obj()
            if (value.isObject) {
                copyField(value as ObjectNode, network, "driver")
                copyField(value, network, "internal")
            }
            networks.set<ObjectNode>(name, network)
        }
    }
    val volumes = runtime.with("volumes")
    runtimeOverlay.path("volumes").fieldsMap().forEach { (name, value) ->
        if (!volumes.has(name)) {
            val volume = obj()
            val device = value.path("driver_opts").path("device").textOrNull()
            if (device != null) volume.put("hostPath", device)
            volumes.set<ObjectNode>(name, volume)
        }
    }
}

fun commandImport(options: Map<String, String>) {
    val moduleDir = Path(required(options, "module")).toAbsolutePath().normalize()
    val metadata = readTree(moduleDir.resolve("stack.module.json"))
    val moduleId = metadata.path("id").asText().ifBlank { fail("module has no id: $moduleDir") }
    val output = Path(options["output"] ?: moduleDir.resolve("stack.runtime.yaml").toString())
    val runtime = obj().put("schemaVersion", 1).put("module", moduleId)
    val observabilityModules = setOf("alertmanager", "alloy", "crowdsec", "grafana", "loki", "node-exporter", "prometheus")
    val coreModules = setOf("stack-foundation", "caddy", "keycloak", "keycloak-auth-gateway", "mariadb", "memcached", "onboarding", "postgres", "postgres-ssd", "valkey")
    runtime.put("target", when (moduleId) { in coreModules -> "core"; in observabilityModules -> "observability"; else -> "apps" })
    runtime.set<ObjectNode>("services", obj())
    runtime.set<ObjectNode>("networks", obj())
    runtime.set<ObjectNode>("volumes", obj())

    val runtimeFiles = mutableListOf<Path>()
    val runtimeOverlayDir = moduleDir.resolve("runtime.overlays")
    if (runtimeOverlayDir.isDirectory()) runtimeFiles += runtimeOverlayDir.listDirectoryEntries("*.yml").sorted()
    if (moduleId == "stack-foundation") {
        listOf("global.settings/networks.yml", "global.settings/volume-init.yml")
            .map(moduleDir::resolve).filter(Path::isRegularFile).forEach(runtimeFiles::add)
    }
    runtimeFiles.forEach { mergeRuntimeOverlayFile(runtime, it) }
    if (runtimeFiles.isEmpty()) {
        runtime.remove("services")
        runtime.remove("networks")
        runtime.remove("volumes")
    }
    writeYaml(output, runtime)
    println("[runtime-import] $moduleId -> $output (${runtime.path("services").size()} services)")
}

fun commandImportWorkspace(options: Map<String, String>) {
    val manifestPath = Path(required(options, "site")).toAbsolutePath().normalize()
    val modulesDir = Path(required(options, "modules-dir")).toAbsolutePath().normalize()
    val manifest = readTree(manifestPath)
    val selected = selectedModuleIds(manifest)
    val discovered = discoverModules(modulesDir)
    val missing = selected.filterNot(discovered::containsKey)
    if (missing.isNotEmpty()) fail("missing selected module checkouts: ${missing.joinToString()}")
    selected.forEach { id ->
        val module = discovered.getValue(id)
        val hasRuntimeSource = module.dir.resolve("runtime.overlays").isDirectory() ||
            (id == "stack-foundation" && module.dir.resolve("global.settings/volume-init.yml").isRegularFile())
        if (hasRuntimeSource) commandImport(mapOf("module" to module.dir.toString()))
    }
}

data class ModuleCheckout(val id: String, val dir: Path, val metadata: ObjectNode, val commit: String, val remote: String)

fun commandOutput(command: List<String>, cwd: Path): String {
    val process = ProcessBuilder(command).directory(cwd.toFile()).redirectErrorStream(true).start()
    val output = process.inputStream.bufferedReader().readText().trim()
    if (process.waitFor() != 0) fail("command failed in $cwd: ${command.joinToString(" ")}\n$output")
    return output
}

fun discoverModules(modulesDir: Path): Map<String, ModuleCheckout> {
    val result = linkedMapOf<String, ModuleCheckout>()
    modulesDir.listDirectoryEntries().filter(Path::isDirectory).sorted().forEach { dir ->
        val metadataPath = dir.resolve("stack.module.json")
        if (!metadataPath.isRegularFile()) return@forEach
        val metadata = readTree(metadataPath)
        val id = metadata.path("id").asText().ifBlank { fail("missing module id in $metadataPath") }
        if (result.containsKey(id)) fail("duplicate module id '$id' in ${result[id]!!.dir} and $dir")
        if (!dir.resolve(".git").isDirectory()) fail("selected module workspace entry is not a Git checkout: $dir")
        result[id] = ModuleCheckout(
            id,
            dir,
            metadata,
            commandOutput(listOf("git", "rev-parse", "HEAD"), dir),
            commandOutput(listOf("git", "remote", "get-url", "origin"), dir)
        )
    }
    return result
}

fun selectedModuleIds(manifest: ObjectNode): List<String> {
    val modules = manifest.path("modules")
    if (!modules.isArray || modules.isEmpty) fail("site manifest modules must be a non-empty explicit array")
    val ids = modules.map {
        if (it.isTextual) it.asText() else it.path("id").asText().ifBlank { fail("invalid site module entry: $it") }
    }
    if (ids.toSet().size != ids.size) fail("site manifest contains duplicate modules")
    return ids
}

fun validateDependencies(selected: Set<String>, modules: List<ModuleCheckout>) {
    modules.forEach { module ->
        module.metadata.path("dependencies").forEach { dependency ->
            if (dependency.asText() !in selected) fail("module '${module.id}' requires explicit module '${dependency.asText()}'")
        }
    }
}

fun mergeResource(existing: ObjectNode, incoming: ObjectNode, kind: String, name: String, module: String): ObjectNode {
    val merged = existing.deepCopy()
    incoming.fieldsMap().forEach { (key, value) ->
        if (merged.has(key) && merged.get(key) != value) fail("conflicting $kind '$name' field '$key' in module '$module'")
        merged.set<JsonNode>(key, value.deepCopy())
    }
    return merged
}

fun storageVariables(siteManifest: ObjectNode, manifestPath: Path): Map<String, String> {
    val stackConfig = siteManifest.path("stackConfig").textOrNull() ?: return emptyMap()
    val configPath = manifestPath.parent.resolve(stackConfig).normalize()
    val config = readTree(configPath)
    val storage = config.path("storage")
    return mapOf(
        "STACK_VOLUME_ROOT" to storage.path("volume_root").asText("/mnt/stack/volumes"),
        "VECTOR_DB_ROOT" to storage.path("vector_dbs").asText("/mnt/stack/vector-dbs"),
        "PG_SSD_ROOT" to storage.path("pg_ssd_root").asText("/mnt/stack/pg-ssd"),
        "QBITTORRENT_DATA_ROOT" to storage.path("custom").path("qbittorrent_data").asText("/mnt/media/qbittorrent"),
        "SEAFILE_MEDIA_ROOT" to storage.path("custom").path("seafile_media").asText("/mnt/media/seafile-media"),
        "JELLYFIN_MEDIA_ROOT" to storage.path("custom").path("jellyfin_media").asText("/mnt/media/jellyfin-media"),
        "DOMAIN" to config.path("runtime").path("domain").asText(),
        "STACK_ADMIN_EMAIL" to config.path("runtime").path("admin_email").asText(),
        "STACK_ADMIN_USER" to config.path("runtime").path("admin_user").asText()
    )
}

fun substitute(value: String, variables: Map<String, String>): String {
    var result = value
    variables.forEach { (key, replacement) ->
        if (replacement.isNotBlank()) {
            result = result.replace("\${$key}", replacement)
                .replace(Regex("\\$\\{$key(?::[-?][^}]*)?}"), replacement)
        }
    }
    return result
}

fun substituteTree(value: JsonNode, variables: Map<String, String>): JsonNode = when {
    value.isTextual -> nodes.textNode(substitute(value.asText(), variables))
    value.isArray -> arr().also { output -> value.forEach { output.add(substituteTree(it, variables)) } }
    value.isObject -> obj().also { output -> value.fieldsMap().forEach { (key, child) -> output.set<JsonNode>(key, substituteTree(child, variables)) } }
    else -> value.deepCopy()
}

fun referencedNamedVolumes(services: ObjectNode): Set<String> {
    val result = linkedSetOf<String>()
    services.fieldsMap().forEach { (_, service) ->
        service.path("volumes").forEach { volume ->
            val source = if (volume.isTextual) volume.asText().substringBefore(':') else volume.path("source").asText()
            if (source.isNotBlank() && !source.startsWith(".") && !source.startsWith("/") && !source.startsWith("%") && !source.contains('$')) result += source
        }
    }
    return result
}

fun validateServicePlacement(name: String, service: ObjectNode) {
    val placement = service.path("placement").asText("rootful")
    if (placement !in setOf("rootful", "rootless")) fail("service '$name' has invalid placement '$placement'")
}

data class RootlessDomainPolicy(
    val name: String,
    val user: String,
    val stateRoot: String,
    val graphRoot: String,
    val volumeRoot: String,
    val modules: Set<String>,
    val allowDependencies: Set<String>,
    val uid: Int?,
    val subuidStart: Int?
)

data class PodmanPolicy(
    val rootfulModules: Set<String>,
    val rootfulServices: Set<String>,
    val domains: List<RootlessDomainPolicy>,
    val serviceDomains: Map<String, String>,
    val maintenanceRoot: String
)

lateinit var activePodmanPolicy: PodmanPolicy

fun stringSet(node: JsonNode, label: String): Set<String> {
    if (!node.isArray) fail("$label must be an array")
    val values = node.map(JsonNode::asText)
    if (values.any(String::isBlank)) fail("$label contains an empty value")
    if (values.size != values.toSet().size) fail("$label contains duplicate values")
    return values.toSet()
}

fun readPodmanPolicy(manifestPath: Path): PodmanPolicy {
    val manifest = readTree(manifestPath)
    val stackConfig = manifest.path("stackConfig").textOrNull()
        ?: fail("site manifest must declare stackConfig for Podman domain policy")
    val configPath = manifestPath.parent.resolve(stackConfig).normalize()
    val podman = readTree(configPath).path("podman")
    if (!podman.isObject) fail("$configPath must define podman")
    val rootfulModules = stringSet(podman.path("rootful_modules"), "podman.rootful_modules")
    val rootfulServices = podman.path("rootful_services").let {
        if (it.isMissingNode) emptySet() else stringSet(it, "podman.rootful_services")
    }
    val domainsNode = podman.path("domains")
    if (!domainsNode.isObject || domainsNode.isEmpty) fail("podman.domains must be a non-empty object")
    val moduleOwners = mutableMapOf<String, String>()
    val users = mutableSetOf<String>()
    val stateRoots = mutableSetOf<String>()
    val graphRoots = mutableSetOf<String>()
    val domains = domainsNode.fieldsMap().map { (name, raw) ->
        if (!name.matches(Regex("[a-z0-9][a-z0-9-]*"))) fail("invalid Podman domain name '$name'")
        val user = raw.path("user").asText().ifBlank { fail("podman domain '$name' has no user") }
        if (!users.add(user)) fail("Podman user '$user' is assigned to more than one domain")
        val stateRoot = raw.path("state_root").asText("/mnt/stack/podman/$name/state")
        val graphRoot = raw.path("graph_root").asText("/mnt/stack/podman/$name/storage")
        val volumeRoot = raw.path("volume_root").asText("/mnt/stack/rootless/$name")
        if (!stateRoot.startsWith("/mnt/stack/") || !graphRoot.startsWith("/mnt/stack/") || !volumeRoot.startsWith("/mnt/stack/")) {
            fail("Podman domain '$name' storage must live below /mnt/stack")
        }
        if (!stateRoots.add(stateRoot)) fail("duplicate Podman state root '$stateRoot'")
        if (!graphRoots.add(graphRoot)) fail("duplicate Podman graph root '$graphRoot'")
        val modules = stringSet(raw.path("modules"), "podman.domains.$name.modules")
        modules.forEach { module -> moduleOwners.put(module, name)?.let { fail("module '$module' belongs to both '$it' and '$name'") } }
        val allowDependencies = raw.path("allow_dependencies").let {
            if (it.isMissingNode) emptySet() else stringSet(it, "podman.domains.$name.allow_dependencies")
        }
        val uid = raw.path("uid").takeUnless(JsonNode::isMissingNode)?.asInt()
        val subuidStart = raw.path("subuid_start").takeUnless(JsonNode::isMissingNode)?.asInt()
        if (uid != null && uid < 1) fail("Podman domain '$name' has invalid uid")
        if (subuidStart != null && subuidStart < 100000) fail("Podman domain '$name' has invalid subuid_start")
        RootlessDomainPolicy(name, user, stateRoot, graphRoot, volumeRoot, modules, allowDependencies, uid, subuidStart)
    }
    domains.forEach { domain ->
        val unknown = domain.allowDependencies - domains.map { it.name }.toSet()
        if (unknown.isNotEmpty()) fail("Podman domain '${domain.name}' allows unknown dependencies: ${unknown.sorted().joinToString()}")
        if (domain.name in domain.allowDependencies) fail("Podman domain '${domain.name}' cannot declare itself as a cross-domain dependency")
    }
    val configuredUids = domains.mapNotNull { it.uid }
    if (configuredUids.size != configuredUids.toSet().size) fail("Podman domain UIDs must be unique")
    val configuredSubuids = domains.mapNotNull { it.subuidStart }
    if (configuredSubuids.size != configuredSubuids.toSet().size) fail("Podman domain subuid_start values must be unique")
    val serviceDomains = mutableMapOf<String, String>()
    podman.path("service_domains").fieldsMap().forEach { (service, domain) ->
        val domainName = domain.asText()
        if (domains.none { it.name == domainName }) fail("service '$service' names unknown domain '$domainName'")
        serviceDomains[service] = domainName
    }
    return PodmanPolicy(
        rootfulModules,
        rootfulServices,
        domains,
        serviceDomains,
        podman.path("maintenance_root").asText("/mnt/lab_debian/stack_lab/stack_work")
    )
}

fun applyPodmanPlacementPolicy(ir: ObjectNode, policy: PodmanPolicy) {
    val moduleDomains = policy.domains.flatMap { domain -> domain.modules.map { it to domain.name } }.toMap()
    val knownModules = ir.path("modules").map { it.path("id").asText() }.toSet()
    val configuredModules = policy.rootfulModules + moduleDomains.keys
    val unknownModules = configuredModules - knownModules
    if (unknownModules.isNotEmpty()) fail("Podman policy names unselected modules: ${unknownModules.sorted().joinToString()}")
    ir.path("services").fieldsMap().forEach { (name, serviceNode) ->
        val service = serviceNode as ObjectNode
        val module = service.path("module").asText()
        if (name in policy.rootfulServices || module in policy.rootfulModules) {
            service.put("placement", "rootful")
        } else {
            val domain = policy.serviceDomains[name] ?: moduleDomains[module]
                ?: fail("service '$name' from module '$module' has no Podman domain owner")
            val domainPolicy = policy.domains.first { it.name == domain }
            service.put("placement", "rootless")
            service.put("rootlessDomain", domain)
            service.put("rootlessUser", domainPolicy.user)
            service.put("rootlessStateRoot", domainPolicy.stateRoot)
            service.put("rootlessGraphRoot", domainPolicy.graphRoot)
            service.put("rootlessVolumeRoot", domainPolicy.volumeRoot)
            service.put("rootlessRuntimeDir", "/run/user/\${${domain.uppercase().replace("-", "_")}_ROOTLESS_UID}/webservices")
        }
        if (name == "caddy") {
            val networks = service.with("networks")
            networks.removeAll()
            networks.set<ObjectNode>("caddy", obj().also { caddyNetwork ->
                caddyNetwork.set<ArrayNode>("aliases", arr().add("caddy"))
            })
        }
    }
}

fun validateNamedVolumes(services: ObjectNode, volumes: ObjectNode) {
    val missing = referencedNamedVolumes(services).filterNot(volumes::has).sorted()
    if (missing.isNotEmpty()) fail("named volumes require explicit declarations: ${missing.joinToString()}")
}

fun sha256(path: Path): String {
    val digest = MessageDigest.getInstance("SHA-256").digest(path.readBytes())
    return digest.joinToString("") { "%02x".format(it) }
}

fun buildIr(manifestPath: Path, modulesDir: Path): Pair<ObjectNode, List<ModuleCheckout>> {
    val manifest = readTree(manifestPath)
    if (manifest.path("schemaVersion").asInt() != 2) fail("site manifest schemaVersion must be 2")
    val requested = selectedModuleIds(manifest)
    val discovered = discoverModules(modulesDir)
    val missing = requested.filterNot(discovered::containsKey)
    if (missing.isNotEmpty()) fail("missing selected module checkouts: ${missing.joinToString()}")
    val modules = requested.map(discovered::getValue)
    validateDependencies(requested.toSet(), modules)

    val ir = obj().put("schemaVersion", 1).put("site", manifest.path("site").asText())
    val moduleRows = arr()
    modules.forEach { module ->
        moduleRows.add(obj().put("id", module.id).put("remote", module.remote).put("commit", module.commit))
    }
    ir.set<ArrayNode>("modules", moduleRows)
    ir.put("unusedCheckoutCount", discovered.keys.count { it !in requested })
    val services = obj()
    val networks = obj()
    val volumes = obj()
    val owners = mutableMapOf<String, String>()
    val variables = storageVariables(manifest, manifestPath)

    modules.forEach { module ->
        val runtimePath = module.dir.resolve("stack.runtime.yaml")
        if (!runtimePath.isRegularFile()) {
            if (module.dir.resolve("runtime.overlays").isDirectory()) fail("runtime-bearing module '${module.id}' lacks stack.runtime.yaml")
            return@forEach
        }
        val runtime = readTree(runtimePath)
        if (runtime.path("schemaVersion").asInt() != 1 || runtime.path("module").asText() != module.id) fail("invalid runtime identity: $runtimePath")
        runtime.path("services").fieldsMap().forEach { (name, raw) ->
            owners.put(name, module.id)?.let { fail("service '$name' is owned by both '$it' and '${module.id}'") }
            val service = substituteTree(raw, variables) as ObjectNode
            service.put("module", module.id)
            service.put("target", runtime.path("target").asText("apps"))
            services.set<ObjectNode>(name, service)
        }
        runtime.path("networks").fieldsMap().forEach { (name, value) ->
            if (!networks.has(name)) networks.set<JsonNode>(name, value.deepCopy())
            else networks.set<ObjectNode>(name, mergeResource(networks.get(name) as ObjectNode, value as ObjectNode, "network", name, module.id))
        }
        runtime.path("volumes").fieldsMap().forEach { (name, value) ->
            val volume = value.deepCopy<ObjectNode>()
            volume.path("hostPath").textOrNull()?.let { volume.put("hostPath", substitute(it, variables)) }
            if (!volumes.has(name)) volumes.set<ObjectNode>(name, volume)
            else volumes.set<ObjectNode>(name, mergeResource(volumes.get(name) as ObjectNode, volume, "volume", name, module.id))
        }
    }
    validateNamedVolumes(services, volumes)
    services.fieldsMap().forEach { (name, service) -> validateServicePlacement(name, service as ObjectNode) }
    services.fieldsMap().forEach { (_, service) ->
        service.path("dependencies").fieldsMap()
            .filter { (_, condition) -> condition.asText() == "completed" }
            .forEach { (dependency, _) ->
                val dependencyService = services.path(dependency) as? ObjectNode
                    ?: fail("completed dependency refers to missing service '$dependency'")
                if (dependencyService.path("lifecycle").asText() == "on-demand") {
                    fail("on-demand service '$dependency' cannot satisfy a completed dependency")
                }
                dependencyService.put("lifecycle", "oneshot")
                dependencyService.put("updatePolicy", "pinned")
            }
    }
    services.fieldsMap().forEach { (name, service) ->
        service.path("dependencies").fieldNames().forEachRemaining { dependency ->
            if (!services.has(dependency)) fail("service '$name' depends on missing service '$dependency'")
        }
    }
    ir.set<ObjectNode>("services", services)
    ir.set<ObjectNode>("networks", networks)
    ir.set<ObjectNode>("volumes", volumes)
    ir.set<ArrayNode>("deferredCapabilities", arr().add("jupyterhub").add("forgejo-runner").add("controller-tests"))
    return ir to modules
}

fun materializeModules(modules: List<ModuleCheckout>, output: Path) {
    val owners = mutableMapOf<Path, String>()
    modules.forEach { module ->
        module.metadata.path("overlays").forEach { overlayNode ->
            val relative = Path(overlayNode.asText())
            if (relative.startsWith("runtime.overlays") || relative.fileName.toString() == "stack.runtime.yaml") return@forEach
            val source = module.dir.resolve(relative).normalize()
            if (!source.startsWith(module.dir) || !source.exists()) fail("unsafe or missing overlay '${relative}' in '${module.id}'")
            val files = if (source.isDirectory()) source.walk().filter(Path::isRegularFile).toList() else listOf(source)
            files.forEach { file ->
                val sourceRelative = module.dir.relativize(file)
                val destinationRelative = when {
                    module.id != "stack-foundation" && sourceRelative.toString() in setOf("stack.config/components.json", "stack.config/components.overlay.json") ->
                        Path("stack.config/components.external/${module.id}.json")
                    module.id != "stack-foundation" && sourceRelative.toString() == "stack.config/service-contracts.json" ->
                        Path("stack.config/service-contracts.external/${module.id}.json")
                    else -> sourceRelative
                }
                val destination = output.resolve("build").resolve(destinationRelative).normalize()
                owners.put(destination, module.id)?.let { fail("overlay collision at $destination between '$it' and '${module.id}'") }
                destination.parent.createDirectories()
                file.copyTo(destination, overwrite = false)
                if (destinationRelative.startsWith(Path("stack.config"))) {
                    val configRelative = Path("runtime/configs").resolve(Path("stack.config").relativize(destinationRelative))
                    val runtimeDestination = output.resolve(configRelative).normalize()
                    owners.put(runtimeDestination, module.id)?.let { fail("overlay collision at $runtimeDestination between '$it' and '${module.id}'") }
                    runtimeDestination.parent.createDirectories()
                    file.copyTo(runtimeDestination, overwrite = false)
                }
            }
        }
    }
}

fun materializeGeneratedBuildArtifacts(modules: List<ModuleCheckout>, output: Path) {
    val generatorRoot = System.getenv("STACK_GENERATOR_ROOT")?.let(Path::of)?.toAbsolutePath()?.normalize()
        ?: fail("STACK_GENERATOR_ROOT is not set")
    val distBuildRoot = generatorRoot.resolve("dist/build").normalize()
    if (!distBuildRoot.isDirectory()) return

    modules.forEach { module ->
        module.metadata.path("overlays").forEach { overlayNode ->
            val overlay = Path(overlayNode.asText())
            if (!overlay.startsWith("stack.kotlin")) return@forEach
            val projectRoot = when {
                overlay.nameCount >= 2 -> Path("stack.kotlin").resolve(overlay.getName(1))
                else -> return@forEach
            }
            val source = distBuildRoot.resolve(projectRoot).normalize()
            if (!source.startsWith(distBuildRoot) || !source.isDirectory()) return@forEach
            val libs = source.resolve("build/libs")
            if (!libs.isDirectory()) return@forEach

            libs.walk().filter(Path::isRegularFile).forEach { file ->
                val relative = distBuildRoot.relativize(file)
                val destination = output.resolve("build").resolve(relative).normalize()
                destination.parent.createDirectories()
                file.copyTo(destination, overwrite = true)
            }
        }
    }
}

fun copyTreeIfPresent(source: Path, destination: Path) {
    if (!source.exists()) return
    if (destination.exists()) destination.toFile().deleteRecursively()
    source.copyToRecursively(destination, followLinks = false, overwrite = true)
}

fun materializeRuntimeRendererInputs(output: Path) {
    val generatorRoot = System.getenv("STACK_GENERATOR_ROOT")?.let(Path::of)?.toAbsolutePath()?.normalize()
        ?: fail("STACK_GENERATOR_ROOT is not set")

    listOf("global.settings", "stack.config").forEach { name ->
        copyTreeIfPresent(output.resolve("build/$name"), output.resolve(name))
    }
    copyTreeIfPresent(generatorRoot.resolve("scripts"), output.resolve("scripts"))

    val buildInfo = output.resolve("build-info.json")
    if (!buildInfo.exists()) {
        writeJson(buildInfo, obj().put("schemaVersion", 1).put("source", "runtime-generator"))
    }
}

fun mergeComponentCatalog(output: Path): ObjectNode {
    val catalogPath = output.resolve("stack.config/components.json")
    val externalDir = output.resolve("stack.config/components.external")
    val catalog = obj()
    catalog.put("schemaVersion", 1)
    catalog.set<ArrayNode>("defaultComponents", arr())
    catalog.set<ObjectNode>("components", obj())

    val catalogSources = mutableListOf<Path>()
    val foundationExternal = externalDir.resolve("stack-foundation.json")
    if (foundationExternal.isRegularFile()) catalogSources.add(foundationExternal)
    else if (catalogPath.isRegularFile()) catalogSources.add(catalogPath)
    if (externalDir.isDirectory()) {
        catalogSources.addAll(externalDir.listDirectoryEntries("*.json")
            .filter { it.fileName.toString() != "stack-foundation.json" }
            .sorted())
    }

    catalogSources.forEach { source ->
        val fragment = readTree(source)
        val defaults = catalog.withArray("defaultComponents")
        fragment.path("defaultComponents").forEach { defaults.add(it.asText()) }
        val components = catalog.get("components") as ObjectNode
        fragment.path("components").fieldsMap().forEach { (name, value) ->
            components.set<JsonNode>(name, value.deepCopy())
        }
    }
    return catalog
}

fun resolveComponentSelection(manifestPath: Path, catalog: ObjectNode): List<String> {
    val manifest = readTree(manifestPath)
    val requested = when {
        manifest.has("components") -> {
            val components = manifest.path("components")
            if (!components.isArray || components.isEmpty) fail("site manifest components must be a non-empty array")
            components.map { it.asText() }
        }
        else -> catalog.path("defaultComponents").map { it.asText() }
    }
    if (requested.isEmpty()) fail("component selection is empty")

    val components = catalog.path("components") as? ObjectNode
        ?: fail("component catalog is missing components")
    val selected = linkedSetOf<String>()
    val queue = ArrayDeque<String>()
    requested.forEach { component ->
        if (!components.has(component)) fail("site manifest selects unknown component '$component'")
        if (selected.add(component)) queue.add(component)
    }
    while (queue.isNotEmpty()) {
        val component = queue.removeFirst()
        components.path(component).path("dependencies").forEach { dependencyNode ->
            val dependency = dependencyNode.asText()
            if (!components.has(dependency)) fail("component '$component' depends on unknown component '$dependency'")
            if (selected.add(dependency)) queue.add(dependency)
        }
    }
    return components.fieldNames().asSequence().filter { selected.contains(it) }.toList()
}

fun materializeComponentLock(manifestPath: Path, output: Path, ir: ObjectNode) {
    val manifest = readTree(manifestPath)
    val moduleIds = ir.path("modules").map { it.path("id").asText() }
    val selected = linkedSetOf<String>().apply {
        addAll(moduleIds)
        if (manifest.has("components")) {
            addAll(resolveComponentSelection(manifestPath, mergeComponentCatalog(output)))
        }
    }
    val componentLock = obj().put("schemaVersion", 1)
    componentLock.set<ArrayNode>("components", arr().addAll(selected.map(nodes::textNode)))
    writeJson(output.resolve("site/components.lock.json"), componentLock)
}

fun materializeGradleBuildInputs(output: Path) {
    val generatorRoot = System.getenv("STACK_GENERATOR_ROOT")?.let(Path::of)?.toAbsolutePath()?.normalize()
        ?: fail("STACK_GENERATOR_ROOT is not set")
    listOf("build.gradle.kts", "settings.gradle.kts", "gradle.properties", "gradlew", "gradlew.bat").forEach { name ->
        val source = generatorRoot.resolve(name)
        if (source.isRegularFile()) {
            source.copyTo(output.resolve("build/$name"), overwrite = true)
            if (name == "gradlew") output.resolve("build/$name").toFile().setExecutable(true)
        }
    }
    copyTreeIfPresent(generatorRoot.resolve("gradle"), output.resolve("build/gradle"))
    output.resolve("build/settings.gradle.kts").writeText(
        """
        rootProject.name = "webservices-generated"

        file("stack.kotlin")
            .takeIf { it.isDirectory }
            ?.listFiles()
            ?.filter { File(it, "build.gradle.kts").isFile }
            ?.sortedBy { it.name }
            ?.forEach { moduleDir ->
                include(":${'$'}{moduleDir.name}")
                project(":${'$'}{moduleDir.name}").projectDir = moduleDir
            }
        """.trimIndent() + "\n"
    )
}

fun buildLocalArtifacts(output: Path) {
    if (System.getenv("STACK_GENERATOR_BUILD_LOCAL_ARTIFACTS") == "0") return
    val buildRoot = output.resolve("build")
    if (!buildRoot.resolve("gradlew").isRegularFile()) fail("cannot build local artifacts without Gradle wrapper")
    val projects = buildRoot.resolve("stack.kotlin")
        .takeIf(Path::isDirectory)
        ?.listDirectoryEntries()
        ?.filter { it.resolve("build.gradle.kts").isRegularFile() && it.resolve("build.gradle.kts").readText().contains("shadowJar") }
        ?.map { ":${it.fileName}:shadowJar" }
        ?.sorted()
        ?: emptyList()
    if (projects.isEmpty()) return
    val command = mutableListOf("./gradlew")
    command += projects
    command += listOf("--no-daemon", "--max-workers=2")
    if (buildRoot.resolve("stack.kotlin/test-runner/build.gradle.kts").isRegularFile()) {
        command += listOf("-x", ":test-runner:test")
    }
    commandOutput(command, buildRoot)
    listOf(".gradle", ".kotlin", "build").forEach { buildRoot.resolve(it).toFile().deleteRecursively() }
    buildRoot.resolve("stack.kotlin")
        .takeIf(Path::isDirectory)
        ?.listDirectoryEntries()
        ?.forEach { project ->
            project.resolve("build")
                .takeIf(Path::isDirectory)
                ?.listDirectoryEntries()
                ?.filter { it.fileName.toString() != "libs" }
                ?.forEach { it.toFile().deleteRecursively() }
        }
}

fun materializeSiteManifest(manifestPath: Path, output: Path) {
    val manifest = readTree(manifestPath)
    val siteDir = output.resolve("site")
    siteDir.createDirectories()
    manifestPath.copyTo(siteDir.resolve("manifest.json"), overwrite = true)
    listOf("stackConfig", "secretStore").forEach { key ->
        val relative = manifest.path(key).textOrNull() ?: fail("site manifest missing $key")
        if (relative.startsWith("/")) fail("site manifest $key must be relative: $relative")
        val source = manifestPath.parent.resolve(relative).normalize()
        if (!source.isRegularFile()) fail("site manifest $key points to missing file: $source")
        val destination = siteDir.resolve(relative).normalize()
        if (!destination.startsWith(siteDir)) fail("site manifest $key escapes site dir: $relative")
        destination.parent.createDirectories()
        source.copyTo(destination, overwrite = true)
    }
}

fun runtimeModelService(service: ObjectNode): ObjectNode {
    val output = obj()
    listOf(
        "image" to "image", "containerName" to "container_name", "environment" to "environment",
        "networks" to "networks", "volumes" to "volumes", "ports" to "ports", "health" to "healthcheck",
        "command" to "command", "entrypoint" to "entrypoint", "restart" to "restart", "workingDir" to "working_dir",
        "user" to "user", "hostname" to "hostname", "dns" to "dns", "extraHosts" to "extra_hosts",
        "tmpfs" to "tmpfs", "readOnly" to "read_only", "init" to "init", "capAdd" to "cap_add",
        "capDrop" to "cap_drop", "securityOpt" to "security_opt", "sysctls" to "sysctls",
        "ulimits" to "ulimits", "shmSize" to "shm_size", "stopGracePeriod" to "stop_grace_period",
        "userns" to "userns_mode", "groupAdd" to "group_add"
    ).forEach { (from, to) -> copyField(service, output, from, to) }
    (output.get("volumes") as? ArrayNode)?.let { volumes ->
        volumes.forEachIndexed { index, mount ->
            if (mount.isTextual && mount.asText().startsWith("%t/")) {
                volumes.set(index, nodes.textNode("\${XDG_RUNTIME_DIR}" + mount.asText().removePrefix("%t")))
            }
        }
    }
    service.get("build")?.let { raw ->
        val build = raw.deepCopy<ObjectNode>()
        build.remove("containerfile")?.let { build.set<JsonNode>("dockerfile", it) }
        build.remove("arguments")?.let { build.set<JsonNode>("args", it) }
        output.set<ObjectNode>("build", build)
    }
    service.get("dependencies")?.let { raw ->
        val dependencies = obj()
        raw.fieldsMap().forEach { (name, condition) ->
            dependencies.set<ObjectNode>(name, obj().put("condition", when (condition.asText()) {
                "healthy" -> "service_healthy"; "completed" -> "service_completed_successfully"; else -> "service_started"
            }))
        }
        output.set<ObjectNode>("depends_on", dependencies)
    }
    service.get("resources")?.let { output.set<ObjectNode>("deploy", obj().set<ObjectNode>("resources", it.deepCopy())) }
    return output
}

fun renderRuntimeModel(ir: ObjectNode, output: Path) {
    val runtimeModel = obj().put("name", "webservices")
    val services = obj()
    ir.path("services").fieldsMap().forEach { (name, service) -> services.set<ObjectNode>(name, runtimeModelService(service as ObjectNode)) }
    runtimeModel.set<ObjectNode>("services", services)
    val networks = obj()
    ir.path("networks").fieldsMap().forEach { (name, value) ->
        val external = value.path("external").asBoolean(false)
        val networkName = value.path("name").textOrNull() ?: "webservices_$name"
        val network = if (external) {
            obj().put("external", true).put("name", networkName)
        } else {
            value.deepCopy<ObjectNode>().put("name", networkName)
        }
        networks.set<ObjectNode>(name, network)
    }
    runtimeModel.set<ObjectNode>("networks", networks)
    val volumes = obj()
    ir.path("volumes").fieldsMap().forEach { (name, value) ->
        val volume = obj().put("name", "webservices_$name")
        value.path("hostPath").textOrNull()?.let {
            volume.put("driver", "local")
            volume.set<ObjectNode>("driver_opts", obj().put("type", "none").put("o", "bind").put("device", it))
        }
        volumes.set<ObjectNode>(name, volume)
    }
    runtimeModel.set<ObjectNode>("volumes", volumes)
    writeYaml(output.resolve("runtime-model.yml"), runtimeModel)
}

fun renderRuntimeOverlayShard(runtimePath: Path, outputDir: Path, predeclaredVolumes: Set<String>) {
    val runtime = readTree(runtimePath)
    if (runtime.path("schemaVersion").asInt() != 1) fail("invalid runtime schema: $runtimePath")
    val moduleId = runtime.path("module").asText().ifBlank { fail("runtime lacks module id: $runtimePath") }
    val runtimeModel = obj()
    val services = obj()
    runtime.path("services").fieldsMap().forEach { (name, service) ->
        services.set<ObjectNode>(name, runtimeModelService(service as ObjectNode))
    }
    runtimeModel.set<ObjectNode>("services", services)
    val volumes = obj()
    runtime.path("volumes").fieldsMap().forEach { (name, value) ->
        if (name in predeclaredVolumes) return@forEach
        val volume = obj()
        value.path("hostPath").textOrNull()?.let {
            volume.put("driver", "local")
            volume.set<ObjectNode>("driver_opts", obj().put("type", "none").put("o", "bind").put("device", it))
        }
        volumes.set<ObjectNode>(name, volume)
    }
    if (volumes.size() > 0) runtimeModel.set<ObjectNode>("volumes", volumes)
    outputDir.createDirectories()
    writeYaml(outputDir.resolve("$moduleId.yml"), runtimeModel)
}

fun commandRenderRuntimeOverlays(options: Map<String, String>) {
    val runtimeDir = Path(required(options, "runtime-dir")).toAbsolutePath().normalize()
    val outputDir = Path(required(options, "output-dir")).toAbsolutePath().normalize()
    val declaredVolumes = options["global-volumes"]?.let { path ->
        val root = readTree(Path(path).toAbsolutePath().normalize())
        root.path("volumes").fieldsMap().map { it.first }.toSet()
    } ?: emptySet()
    if (!runtimeDir.isDirectory()) return
    runtimeDir.listDirectoryEntries("*.yaml").sorted().forEach { renderRuntimeOverlayShard(it, outputDir, declaredVolumes) }
}

fun systemdQuote(value: String): String = "\"" + value
    .replace("\$\$", "\$")
    .replace("%", "%%")
    .replace("$", "\$\$")
    .replace("\\", "\\\\")
    .replace("\"", "\\\"")
    .replace("\n", "\\n") + "\""
fun quadletLiteral(value: String): String =
    value.replace("%", "%%").replace("%%t", "%t")

data class PodmanDomain(
    val name: String,
    val quadletDir: String,
    val stateRoot: String,
    val rootlessUser: String?,
    val envFilePrefix: String,
    val targetInstall: String,
    val releaseRoot: String,
    val graphRoot: String? = null,
    val volumeRoot: String? = null
)

val rootfulDomain = PodmanDomain(
    name = "rootful",
    quadletDir = "quadlet/rootful",
    stateRoot = "/var/lib/webservices",
    rootlessUser = null,
    envFilePrefix = "/run/webservices",
    targetInstall = "multi-user.target",
    releaseRoot = "/var/lib/webservices/current"
)

val rootlessDomains: List<PodmanDomain>
    get() = activePodmanPolicy.domains.map {
        PodmanDomain(
            name = it.name,
            quadletDir = "quadlet/rootless-${it.name}",
            stateRoot = it.stateRoot,
            rootlessUser = it.user,
            envFilePrefix = "%t/webservices",
            targetInstall = "default.target",
            releaseRoot = "${it.stateRoot}/current",
            graphRoot = it.graphRoot,
            volumeRoot = it.volumeRoot
        )
    }

val rootlessDomainByName: Map<String, PodmanDomain>
    get() = rootlessDomains.associateBy { it.name }

fun podmanDomainForService(service: JsonNode): PodmanDomain =
    if (service.path("placement").asText("rootful") == "rootful") rootfulDomain
    else rootlessDomainByName[service.path("rootlessDomain").asText()]
        ?: fail("service has unknown rootless domain '${service.path("rootlessDomain").asText()}'")

data class LoopbackEndpoint(val service: String, val containerPort: String, val hostPort: Int)
fun podmanNetworkName(domain: PodmanDomain, name: String): String =
    if (domain.name == "rootful") "webservices_$name" else "webservices_${domain.name}_$name"

fun qualifiedImage(image: String, updatePolicy: String): String {
    var ref = if (updatePolicy == "registry") image.substringBefore('@') else image
    val first = ref.substringBefore('/')
    if (!ref.contains('/')) ref = "docker.io/library/$ref"
    else if (!first.contains('.') && !first.contains(':') && first != "localhost") ref = "docker.io/$ref"
    return ref
}

fun rootlessHostPath(name: String, domain: PodmanDomain): String =
    "${domain.volumeRoot ?: fail("rootless domain '${domain.name}' has no volume root")}/$name"

fun resolvedVolumeSource(source: String, allVolumes: JsonNode, domain: PodmanDomain): String {
    val volume = allVolumes.path(source)
    val hostPath = volume.path("hostPath").textOrNull() ?: return runtimeBindPath(source, domain)
    if (domain.name == "rootful") return hostPath
    return if (volume.path("rootlessStrategy").asText("copy") == "shared") hostPath else rootlessHostPath(source, domain)
}

fun rootlessCopyVolume(source: String, allVolumes: JsonNode, domain: PodmanDomain): Boolean {
    if (domain.name == "rootful") return false
    val volume = allVolumes.path(source)
    return volume.has("hostPath") && volume.path("rootlessStrategy").asText("copy") != "shared"
}

fun volumeLine(volume: JsonNode, allVolumes: JsonNode, domain: PodmanDomain): String {
    if (volume.isTextual) {
        val raw = volume.asText()
        val parts = raw.split(':')
        val source = parts.first()
        val resolved = resolvedVolumeSource(source, allVolumes, domain)
        val tailParts = parts.drop(1).toMutableList()
        if (rootlessCopyVolume(source, allVolumes, domain) && "ro" !in tailParts && "U" !in tailParts) tailParts += "U"
        val tail = tailParts.joinToString(":")
        return if (tail.isBlank()) resolved else "$resolved:$tail"
    }
    val source = volume.path("source").asText()
    val resolved = resolvedVolumeSource(source, allVolumes, domain)
    val suffix = when {
        volume.path("read_only").asBoolean(false) -> ":ro"
        rootlessCopyVolume(source, allVolumes, domain) -> ":U"
        else -> ""
    }
    return "$resolved:${volume.path("target").asText()}$suffix"
}

fun runtimeBindPath(source: String, domain: PodmanDomain = rootfulDomain): String = when {
    source.startsWith("./configs/") -> "${domain.releaseRoot}/runtime/configs/${source.removePrefix("./configs/")}"
    source.startsWith("./build/") -> "${domain.releaseRoot}/build/${source.removePrefix("./build/")}"
    source == "./repos" || source.startsWith("./repos/") -> "${domain.releaseRoot}/${source.removePrefix("./")}"
    source.startsWith("./stack.") -> "${domain.releaseRoot}/build/${source.removePrefix("./")}"
    else -> source
}

fun commandValue(value: JsonNode): String = when {
    value.isArray -> value.joinToString(" ") { systemdQuote(it.asText()) }
    value.isTextual -> systemdQuote(value.asText())
    else -> systemdQuote(value.toString())
}

fun shellWords(value: String): List<String> {
    val words = mutableListOf<String>()
    val current = StringBuilder()
    var quote: Char? = null
    var escaped = false
    value.forEach { char ->
        when {
            escaped -> {
                current.append(char)
                escaped = false
            }
            char == '\\' -> escaped = true
            quote != null && char == quote -> quote = null
            quote != null -> current.append(char)
            char == '\'' || char == '"' -> quote = char
            char.isWhitespace() -> {
                if (current.isNotEmpty()) {
                    words += current.toString()
                    current.clear()
                }
            }
            else -> current.append(char)
        }
    }
    if (escaped) current.append('\\')
    if (quote != null) fail("unterminated quote in command: $value")
    if (current.isNotEmpty()) words += current.toString()
    return words
}

fun healthCommand(health: JsonNode): String? {
    val test = health.path("test")
    if (!test.isArray || test.isEmpty) return null
    val parts = test.map(JsonNode::asText)
    return when (parts.first()) {
        "NONE" -> null
        "CMD-SHELL" -> parts.drop(1).joinToString(" ")
        "CMD" -> parts.drop(1).joinToString(" ")
        else -> parts.joinToString(" ")
    }
}

fun renderEnvironmentTemplate(name: String, service: ObjectNode, output: Path) {
    val environment = service.path("environment")
    if (!environment.isObject || environment.isEmpty) return
    val lines = environment.fieldsMap().sortedBy { it.first }.joinToString("\n") { (key, value) ->
        val rendered = if (value.isNull) "\${$key}" else value.asText().replace("\n", "\\n")
        "$key=$rendered"
    }
    output.resolve("runtime-env/$name.env.template").apply { parent.createDirectories(); writeText(lines + "\n") }
}

fun loopbackEndpoints(ir: ObjectNode, output: Path): Map<String, List<LoopbackEndpoint>> {
    val caddyFile = output.resolve("runtime/configs/caddy/Caddyfile")
    if (!caddyFile.isRegularFile()) return emptyMap()
    val knownServices = ir.path("services").fieldsMap().map { it.first }.toSet()
    val endpointPattern = Regex("\\b([a-z0-9][a-z0-9-]*):(\\d{2,5})\\b")
    val endpoints = linkedMapOf<Pair<String, String>, LoopbackEndpoint>()
    endpointPattern.findAll(caddyFile.readText()).forEach { match ->
        val service = match.groupValues[1]
        val port = match.groupValues[2]
        if (service in knownServices) {
            endpoints.getOrPut(service to port) {
                LoopbackEndpoint(service, port, 18080 + endpoints.size)
            }
        }
    }
    if (endpoints.isEmpty()) return emptyMap()
    var rewritten = caddyFile.readText()
    endpoints.values.forEach { endpoint ->
        rewritten = rewritten.replace(
            Regex("\\b${Regex.escape(endpoint.service)}:${Regex.escape(endpoint.containerPort)}\\b"),
            "127.0.0.1:${endpoint.hostPort}"
        )
    }
    caddyFile.writeText(rewritten)
    val rows = arr()
    endpoints.values.sortedWith(compareBy({ it.service }, { it.containerPort })).forEach { endpoint ->
        rows.add(obj()
            .put("service", endpoint.service)
            .put("containerPort", endpoint.containerPort)
            .put("hostPort", endpoint.hostPort)
            .put("url", "http://127.0.0.1:${endpoint.hostPort}"))
    }
    writeJson(output.resolve("podman-loopback-endpoints.json"), obj().set<ArrayNode>("endpoints", rows))
    return endpoints.values.groupBy { it.service }
}

fun stopTimeoutSeconds(node: JsonNode): Long? {
    if (node.isMissingNode || node.isNull) return null
    if (node.isIntegralNumber) return node.asLong().coerceAtLeast(1)
    val raw = node.asText().trim()
    val part = Regex("(\\d+(?:\\.\\d+)?)(us|ms|s|m|h)")
    val matches = part.findAll(raw).toList()
    if (matches.isEmpty() || matches.joinToString("") { it.value } != raw) {
        fail("invalid stopGracePeriod '$raw'; expected a Compose duration such as 30s or 1m30s")
    }
    val seconds = matches.sumOf { match ->
        val value = match.groupValues[1].toDouble()
        when (match.groupValues[2]) {
            "us" -> value / 1_000_000.0
            "ms" -> value / 1_000.0
            "s" -> value
            "m" -> value * 60.0
            "h" -> value * 3_600.0
            else -> fail("unsupported stopGracePeriod unit in '$raw'")
        }
    }
    return kotlin.math.ceil(seconds).toLong().coerceAtLeast(1)
}

fun renderQuadletService(name: String, service: ObjectNode, ir: ObjectNode, output: Path, domain: PodmanDomain, loopbacks: Map<String, List<LoopbackEndpoint>>) {
    val quadlet = output.resolve("${domain.quadletDir}/webservices-$name.container")
    quadlet.parent.createDirectories()
    val dependencies = service.path("dependencies").fieldsMap()
        .filter { (dependency, _) ->
            podmanDomainForService(ir.path("services").path(dependency)).name == domain.name
        }
    val lines = mutableListOf<String>()
    lines += "[Unit]"
    lines += "Description=Webservices container: $name"
    dependencies.forEach { (dependency, _) ->
        lines += "Requires=webservices-$dependency.service"
        lines += "After=webservices-$dependency.service"
    }
    lines += "PartOf=webservices-${service.path("target").asText("apps")}.target"
    lines += ""
    lines += "[Container]"
    service.path("build").takeUnless(JsonNode::isMissingNode)?.let { lines += "Image=webservices-$name.build" }
        ?: lines.add("Image=${qualifiedImage(service.path("image").asText(), service.path("updatePolicy").asText("pinned"))}")
    lines += "ContainerName=$name"
    if (service.path("lifecycle").asText() == "daemon" && service.path("updatePolicy").asText() == "registry") lines += "AutoUpdate=registry"
    if (service.path("environment").isObject && !service.path("environment").isEmpty) lines += "EnvironmentFile=${domain.envFilePrefix}/$name.env"
    val hostNetwork = name == "caddy" || service.path("hostNetwork").asBoolean(false)
    if (hostNetwork) {
        lines += "Network=host"
    } else {
        service.path("networks").let { networkNode ->
            if (networkNode.isArray) networkNode.forEach { lines += "Network=webservices-${it.asText()}.network" }
            else networkNode.fieldsMap().forEach { (network, config) ->
                lines += "Network=webservices-$network.network"
                config.path("aliases").forEach { lines += "NetworkAlias=${it.asText()}" }
            }
        }
    }
    service.path("volumes").forEach { lines += "Volume=${quadletLiteral(volumeLine(it, ir.path("volumes"), domain))}" }
    lines += "PodmanArgs=--image-volume=ignore"
    service.path("ephemeralImageVolumes").forEach { lines += "Tmpfs=${it.asText()}" }
    service.path("userns").textOrNull()?.let { lines += "UserNS=$it" }
    service.path("groupAdd").forEach { lines += "GroupAdd=${it.asText()}" }
    if (!hostNetwork) {
        service.path("ports").forEach { port ->
            val value = if (port.isTextual) port.asText() else {
                val protocol = port.path("protocol").asText("tcp").let { if (it == "tcp") "" else "/$it" }
                "${port.path("published").asText()}:${port.path("target").asText()}$protocol"
            }
            lines += "PublishPort=$value"
        }
    }
    loopbacks[name].orEmpty().forEach { endpoint ->
        lines += "PublishPort=127.0.0.1:${endpoint.hostPort}:${endpoint.containerPort}"
    }
    service.path("extraHosts").forEach { lines += "AddHost=${it.asText().replace("host-gateway", "host-gateway")}" }
    service.path("dns").let { if (it.isArray) it.forEach { dns -> lines += "DNS=${dns.asText()}" } else if (it.isTextual) lines += "DNS=${it.asText()}" }
    service.path("tmpfs").forEach { lines += "Tmpfs=${it.asText()}" }
    service.path("capAdd").forEach { lines += "AddCapability=${it.asText()}" }
    service.path("capDrop").forEach { lines += "DropCapability=${it.asText()}" }
    if (service.path("readOnly").asBoolean(false)) lines += "ReadOnly=true"
    if (service.path("init").asBoolean(false)) lines += "RunInit=true"
    service.path("user").textOrNull()?.let { lines += "User=$it" }
    service.path("workingDir").textOrNull()?.let { lines += "WorkingDir=$it" }
    service.path("hostname").textOrNull()?.let { lines += "HostName=$it" }
    val entrypoint = service.path("entrypoint")
    val command = service.path("command")
    val execParts = mutableListOf<String>()
    if (!entrypoint.isMissingNode) {
        if (entrypoint.isArray && !entrypoint.isEmpty) {
            lines += "Entrypoint=${systemdQuote(entrypoint.first().asText())}"
            entrypoint.drop(1).forEach { execParts += it.asText() }
        } else lines += "Entrypoint=${systemdQuote(entrypoint.asText())}"
    }
    if (!command.isMissingNode) {
        if (command.isArray) command.forEach { execParts += it.asText() } else execParts += shellWords(command.asText())
    }
    if (execParts.isNotEmpty()) lines += "Exec=${execParts.joinToString(" ") { systemdQuote(it) }}"
    stopTimeoutSeconds(service.path("stopGracePeriod"))?.let { lines += "StopTimeout=$it" }
    // Shell healthcheck fragments need a dedicated Podman translation pass.
    // For the rootful cutover, systemd owns process liveness and does not gate startup on container health.
    lines += "LogDriver=journald"
    lines += ""
    lines += "[Service]"
    if (service.path("lifecycle").asText() == "oneshot") {
        lines += "Type=oneshot"
        lines += "RemainAfterExit=yes"
        lines += "Restart=no"
    } else {
        lines += "Restart=${when (service.path("restart").asText()) { "always", "unless-stopped" -> "always"; else -> "on-failure" }}"
        lines += "RestartSec=5s"
        lines += "TimeoutStartSec=900"
        lines += "TimeoutStopSec=120"
    }
    lines += ""
    lines += "[Install]"
    if (service.path("lifecycle").asText() != "on-demand") lines += "WantedBy=webservices-${service.path("target").asText("apps")}.target"
    quadlet.writeText(lines.joinToString("\n", postfix = "\n"))
    renderEnvironmentTemplate(name, service, output)

    service.path("build").takeUnless(JsonNode::isMissingNode)?.let { build ->
        val buildLines = mutableListOf("[Build]")
        buildLines += "ImageTag=localhost/webservices/$name:bundle"
        build.path("context").textOrNull()?.let {
            val relativeContext = it.removePrefix("./").let { context -> if (context == "." || context == "build") "" else context }
            val workingDirectory = "${domain.releaseRoot}/build" + if (relativeContext.isBlank()) "" else "/$relativeContext"
            buildLines += "SetWorkingDirectory=${systemdQuote(workingDirectory)}"
        }
        build.path("containerfile").textOrNull()?.let { buildLines += "File=${systemdQuote(it)}" }
        output.resolve("${domain.quadletDir}/webservices-$name.build").writeText(buildLines.joinToString("\n", postfix = "\n"))
    }
}

fun renderPodman(ir: ObjectNode, output: Path) {
    val loopbacks = loopbackEndpoints(ir, output)
    (listOf(rootfulDomain) + rootlessDomains).forEach { domain ->
        val usedNetworks = ir.path("services").fieldsMap()
            .filter { (_, service) -> podmanDomainForService(service).name == domain.name }
            .flatMap { (_, service) ->
                val networks = service.path("networks")
                if (networks.isArray) networks.map(JsonNode::asText) else networks.fieldsMap().map { it.first }
            }
            .toSet()
        ir.path("networks").fieldsMap().filter { it.first in usedNetworks }.forEach { (name, value) ->
            val lines = mutableListOf("[Network]", "NetworkName=${podmanNetworkName(domain, name)}", "Driver=${value.path("driver").asText("bridge")}")
            if (value.path("internal").asBoolean(false)) lines += "Internal=true"
            output.resolve("${domain.quadletDir}/webservices-$name.network").apply { parent.createDirectories(); writeText(lines.joinToString("\n", postfix = "\n")) }
        }
        ir.path("services").fieldsMap()
            .filter { (_, service) ->
                podmanDomainForService(service).name == domain.name &&
                    service.path("lifecycle").asText() != "on-demand"
            }
            .forEach { (name, service) -> renderQuadletService(name, service as ObjectNode, ir, output, domain, loopbacks) }
        listOf("core", "apps", "observability").forEach { target ->
            val targetServices = ir.path("services").fieldsMap()
                .filter { (_, service) ->
                    podmanDomainForService(service).name == domain.name &&
                        service.path("target").asText("apps") == target &&
                        service.path("lifecycle").asText() != "on-demand"
                }
                .map { (name, _) -> "webservices-$name.service" }
                .sorted()
            val wants = if (targetServices.isEmpty()) "" else "Wants=${targetServices.joinToString(" ")}\n"
            output.resolve("${domain.quadletDir}/webservices-$target.target").writeText("[Unit]\nDescription=Webservices ${target.replaceFirstChar(Char::uppercase)} (${domain.name})\nPartOf=webservices.target\n${wants}\n[Install]\nWantedBy=webservices.target\n")
        }
        output.resolve("${domain.quadletDir}/webservices.target").writeText("[Unit]\nDescription=Platform Zero webservices stack (${domain.name})\nWants=webservices-core.target webservices-apps.target webservices-observability.target\n\n[Install]\nWantedBy=${domain.targetInstall}\n")
    }
    val generatorRoot = System.getenv("STACK_GENERATOR_ROOT")?.let(Path::of)
        ?: fail("STACK_GENERATOR_ROOT is not set")
    generatorRoot.resolve("runtime-generator/podman-ops").copyToRecursively(
        output.resolve("ops"),
        followLinks = false,
        overwrite = false
    )
    generatorRoot.resolve("ops/host-admin/provision-domain-accounts.sh")
        .copyTo(output.resolve("ops/provision-domain-accounts.sh"), overwrite = true)
    generatorRoot.resolve("ops/maintenance/materialize-workspaces.py")
        .copyTo(output.resolve("ops/materialize-workspaces.py"), overwrite = true)
}

fun repositoryRow(name: String, remote: String, commit: String, writable: Boolean): ObjectNode =
    obj().put("name", name).put("remote", remote).put("commit", commit).put("writable", writable)

fun findGitRoot(path: Path): Path? {
    var current = if (path.isDirectory()) path else path.parent
    while (current != null) {
        if (current.resolve(".git").isDirectory()) return current
        current = current.parent
    }
    return null
}

fun localRepositoryRow(name: String, path: Path, writable: Boolean): ObjectNode {
    val root = findGitRoot(path) ?: fail("maintenance repository '$name' is not inside a Git checkout: $path")
    return repositoryRow(
        name,
        commandOutput(listOf("git", "remote", "get-url", "origin"), root),
        commandOutput(listOf("git", "rev-parse", "HEAD"), root),
        writable
    )
}

fun writeDomainMetadata(ir: ObjectNode, modules: List<ModuleCheckout>, manifestPath: Path, output: Path) {
    val moduleById = modules.associateBy { it.id }
    val domainRows = arr()
    activePodmanPolicy.domains.forEach { policy ->
        val services = ir.path("services").fieldsMap()
            .filter { (_, service) -> service.path("rootlessDomain").asText() == policy.name }
            .map { it.first }
            .sorted()
        domainRows.add(obj().also { row ->
            row.put("name", policy.name)
            row.put("user", policy.user)
            row.put("stateRoot", policy.stateRoot)
            row.put("graphRoot", policy.graphRoot)
            row.put("volumeRoot", policy.volumeRoot)
            policy.uid?.let { row.put("uid", it) }
            policy.subuidStart?.let { row.put("subuidStart", it) }
            row.set<ArrayNode>("modules", arr().addAll(policy.modules.sorted().map(nodes::textNode)))
            row.set<ArrayNode>("services", arr().addAll(services.map(nodes::textNode)))
            row.set<ArrayNode>("allowDependencies", arr().addAll(policy.allowDependencies.sorted().map(nodes::textNode)))
        })
    }
    writeJson(output.resolve("podman-domains.json"), obj().put("schemaVersion", 1).set<ArrayNode>("domains", domainRows))

    val dependencyRows = arr()
    ir.path("services").fieldsMap().forEach { (consumer, service) ->
        val consumerDomain = podmanDomainForService(service).name
        service.path("dependencies").fieldsMap().forEach dependency@{ (provider, condition) ->
            val providerService = ir.path("services").path(provider)
            if (providerService.isMissingNode) fail("service '$consumer' depends on unknown service '$provider'")
            val providerDomain = podmanDomainForService(providerService).name
            if (consumerDomain == providerDomain) return@dependency
            if (consumerDomain != "rootful" && providerDomain != "rootful") {
                val allowed = activePodmanPolicy.domains.first { it.name == consumerDomain }.allowDependencies
                if (providerDomain !in allowed) {
                    fail("undeclared cross-domain dependency: $consumerDomain/$consumer -> $providerDomain/$provider")
                }
            }
            dependencyRows.add(obj()
                .put("consumerDomain", consumerDomain)
                .put("consumerService", consumer)
                .put("providerDomain", providerDomain)
                .put("providerService", provider)
                .put("condition", condition.asText()))
        }
    }
    writeJson(output.resolve("podman-domain-dependencies.json"), obj().put("schemaVersion", 1).set<ArrayNode>("dependencies", dependencyRows))

    val generatorRoot = Path(System.getenv("STACK_GENERATOR_ROOT") ?: fail("STACK_GENERATOR_ROOT is not set"))
    val siteMetadata = manifestPath.parent.resolve(".webservices-generator.json").takeIf(Path::isRegularFile)?.let(::readTree)
    val siteRow = findGitRoot(manifestPath)?.let { localRepositoryRow("site-config", it, false) }
        ?: siteMetadata?.let {
            repositoryRow(
                "site-config",
                it.path("moduleManifestRemote").asText().ifBlank { fail("site generator metadata has no moduleManifestRemote") },
                it.path("moduleManifestCommit").asText().ifBlank { fail("site generator metadata has no moduleManifestCommit") },
                false
            )
        }
        ?: repositoryRow("site-config", "unresolved:site-config", sha256(manifestPath), false)
    val generatorRow = findGitRoot(generatorRoot)?.let { localRepositoryRow("sso-stack-generator", it, false) }
        ?: siteMetadata?.let {
            repositoryRow(
                "sso-stack-generator",
                it.path("generatorRemote").asText().ifBlank { fail("site generator metadata has no generatorRemote") },
                it.path("generatorCommit").asText().ifBlank { fail("site generator metadata has no generatorCommit") },
                false
            )
        }
        ?: repositoryRow(
            "sso-stack-generator",
            "unresolved:sso-stack-generator",
            sha256(generatorRoot.resolve("runtime-generator/stack-generator.main.kts")),
            false
        )
    val baseline = listOf(
        generatorRow,
        siteRow
    )
    fun reposFor(moduleIds: Set<String>): ArrayNode = arr().also { repos ->
        baseline.forEach { repos.add(it.deepCopy()) }
        moduleIds.sorted().forEach { id ->
            val module = moduleById[id] ?: fail("maintenance workspace references unknown module '$id'")
            repos.add(repositoryRow(module.metadata.path("repo").asText(module.dir.fileName.toString()), module.remote, module.commit, true))
        }
    }
    val workspaces = arr()
    workspaces.add(obj().put("name", "control").put("role", "control").set<ArrayNode>("repositories", arr().also { rows ->
        baseline.forEach { rows.add(it.deepCopy().also { row -> row.put("writable", true) }) }
    }))
    workspaces.add(obj().put("name", "host").put("role", "host").set<ArrayNode>("repositories", reposFor(activePodmanPolicy.rootfulModules)))
    activePodmanPolicy.domains.forEach { domain ->
        workspaces.add(obj().also { row ->
            row.put("name", domain.name)
            row.put("role", "domain")
            row.put("serviceAccount", domain.user)
            row.set<ArrayNode>("services", domainRows.first { it.path("name").asText() == domain.name }.path("services").deepCopy())
            row.set<ArrayNode>("repositories", reposFor(domain.modules))
        })
    }
    writeJson(output.resolve("maintenance-workspaces.json"), obj()
        .put("schemaVersion", 1)
        .put("root", activePodmanPolicy.maintenanceRoot)
        .set<ArrayNode>("workspaces", workspaces))
}

fun replaceDirectory(staging: Path, output: Path) {
    if (output.exists()) output.toFile().deleteRecursively()
    try {
        Files.move(staging, output, StandardCopyOption.ATOMIC_MOVE)
    } catch (_: Exception) {
        Files.move(staging, output)
    }
}

fun commandGenerate(options: Map<String, String>) {
    val manifest = Path(required(options, "site")).toAbsolutePath().normalize()
    val modulesDir = Path(required(options, "modules-dir")).toAbsolutePath().normalize()
    val backend = required(options, "backend")
    if (backend != "podman") fail("backend must be podman")
    val output = Path(required(options, "output")).toAbsolutePath().normalize()
    val staging = output.resolveSibling(".${output.fileName}.staging-${ProcessHandle.current().pid()}")
    if (staging.exists()) staging.toFile().deleteRecursively()
    staging.createDirectories()
    try {
        activePodmanPolicy = readPodmanPolicy(manifest)
        val (ir, modules) = buildIr(manifest, modulesDir)
        applyPodmanPlacementPolicy(ir, activePodmanPolicy)
        writeJson(staging.resolve("stack.ir.json"), ir)
        materializeSiteManifest(manifest, staging)
        materializeModules(modules, staging)
        materializeGradleBuildInputs(staging)
        buildLocalArtifacts(staging)
        materializeGeneratedBuildArtifacts(modules, staging)
        materializeRuntimeRendererInputs(staging)
        materializeComponentLock(manifest, staging, ir)
        renderRuntimeModel(ir, staging)
        if (backend == "podman") renderPodman(ir, staging)
        writeDomainMetadata(ir, modules, manifest, staging)
        val metadata = obj()
        metadata.put("schemaVersion", 1)
        metadata.put("backend", backend)
        metadata.put("irSha256", sha256(staging.resolve("stack.ir.json")))
        metadata.set<ArrayNode>("deferredCapabilities", ir.path("deferredCapabilities").deepCopy())
        writeJson(staging.resolve("bundle.json"), metadata)
        replaceDirectory(staging, output)
        println("[stack-generator] generated $backend bundle at $output (${ir.path("services").size()} services)")
    } catch (error: Throwable) {
        staging.toFile().deleteRecursively()
        throw error
    }
}

val (command, options) = parseArgs(args)
when (command) {
    "generate" -> commandGenerate(options)
    "import-runtime-overlays" -> commandImport(options)
    "import-workspace" -> commandImportWorkspace(options)
    "render-runtime-model" -> commandRenderRuntimeOverlays(options)
    else -> fail("unknown command '$command' (expected generate, import-runtime-overlays, import-workspace, or render-runtime-model)")
}

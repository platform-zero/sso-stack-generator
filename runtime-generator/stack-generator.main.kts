@file:OptIn(kotlin.io.path.ExperimentalPathApi::class)

import com.fasterxml.jackson.core.JsonGenerator
import com.fasterxml.jackson.core.JsonParser
import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.SerializationFeature
import com.fasterxml.jackson.databind.node.ArrayNode
import com.fasterxml.jackson.databind.node.JsonNodeFactory
import com.fasterxml.jackson.databind.node.ObjectNode
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory
import java.io.File
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.nio.file.attribute.PosixFilePermission
import java.security.MessageDigest
import kotlin.io.path.*

val json = ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT)
    .enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION)
val yaml = ObjectMapper(YAMLFactory().disable(JsonGenerator.Feature.AUTO_CLOSE_TARGET))
    .enable(SerializationFeature.INDENT_OUTPUT)
    .enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION)
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
        "userns_mode" to "userns", "group_add" to "groupAdd", "devices" to "devices", "pid" to "pidMode"
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
        if (!dir.resolve(".git").exists()) fail("selected module workspace entry is not a Git checkout: $dir")
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

fun excludedIds(manifest: ObjectNode, key: String): Set<String> {
    if (!manifest.has(key)) return emptySet()
    val values = manifest.path(key)
    if (!values.isArray || values.any { !it.isTextual || !it.asText().matches(Regex("[a-z0-9][a-z0-9-]*")) }) {
        fail("site manifest $key must be an explicit identifier array")
    }
    val ids = values.map { it.asText() }
    if (ids.toSet().size != ids.size) fail("site manifest $key contains duplicates")
    return ids.toSet()
}

fun selectedModuleIds(manifest: ObjectNode): List<String> {
    val modules = manifest.path("modules")
    if (!modules.isArray || modules.isEmpty) fail("site manifest modules must be a non-empty explicit array")
    val ids = modules.map {
        if (it.isTextual) it.asText() else it.path("id").asText().ifBlank { fail("invalid site module entry: $it") }
    }
    if (ids.toSet().size != ids.size) fail("site manifest contains duplicate modules")
    val forbidden = excludedIds(manifest, "excludedModules")
    ids.firstOrNull { it in forbidden }?.let { fail("site manifest selects excluded module '$it'") }
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
    val subuidStart: Int?,
    val maintenanceLane: String,
    val hostCapabilities: Set<String>
)

data class CrossDomainEndpointPolicy(
    val service: String,
    val containerPort: Int,
    val hostPort: Int,
    val protocol: String,
    val consumers: Set<String>
)

data class PodmanPolicy(
    val rootfulModules: Set<String>,
    val rootfulServices: Set<String>,
    val domains: List<RootlessDomainPolicy>,
    val serviceDomains: Map<String, String>,
    val crossDomainEndpoints: List<CrossDomainEndpointPolicy>,
    val maintenanceRoot: String,
    val defaultMemory: String?,
    val defaultCpus: String?,
    val unitPrefix: String,
    val rootfulStateRoot: String,
    val rootfulGraphRoot: String?,
    val rootfulRunRoot: String?,
    val portMap: Map<Int, Int>,
    val venueVolumeRoot: String?,
    val venuePgSsdRoot: String?,
    val venueVectorDbsRoot: String?,
    val venueControlSocketRoot: String?,
    val venueLogRoot: String?,
    val standalone: Boolean
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
    val siteConfig = readTree(configPath)
    val podman = siteConfig.path("podman")
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
        val maintenanceLane = raw.path("maintenance_lane").asText(name)
        if (!maintenanceLane.matches(Regex("[a-z0-9][a-z0-9-]*"))) fail("Podman domain '$name' has invalid maintenance_lane")
        val hostCapabilities = raw.path("host_capabilities").let {
            if (it.isMissingNode) emptySet() else stringSet(it, "podman.domains.$name.host_capabilities")
        }
        val unsupportedCapabilities = hostCapabilities - setOf("kvm")
        if (unsupportedCapabilities.isNotEmpty()) fail("Podman domain '$name' has unsupported host capabilities: ${unsupportedCapabilities.sorted().joinToString()}")
        RootlessDomainPolicy(name, user, stateRoot, graphRoot, volumeRoot, modules, allowDependencies, uid, subuidStart, maintenanceLane, hostCapabilities)
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
    val endpointKeys = mutableSetOf<String>()
    val endpointPorts = mutableSetOf<Pair<String, Int>>()
    val crossDomainEndpoints = podman.path("cross_domain_endpoints").let { endpointNode ->
        if (endpointNode.isMissingNode) emptyList() else {
            if (!endpointNode.isArray) fail("podman.cross_domain_endpoints must be an array")
            endpointNode.mapIndexed { index, raw ->
                val label = "podman.cross_domain_endpoints[$index]"
                val service = raw.path("service").asText().ifBlank { fail("$label has no service") }
                val containerPort = raw.path("container_port").asInt()
                val hostPort = raw.path("host_port").asInt()
                val protocol = raw.path("protocol").asText("tcp")
                val consumers = stringSet(raw.path("consumers"), "$label.consumers")
                if (containerPort !in 1..65535 || hostPort !in 1024..65535) fail("$label has an invalid port")
                if (protocol !in setOf("tcp", "udp")) fail("$label protocol must be tcp or udp")
                if (consumers.isEmpty()) fail("$label must name at least one consumer domain")
                val unknownConsumers = consumers - (domains.map { it.name }.toSet() + "rootful")
                if (unknownConsumers.isNotEmpty()) fail("$label names unknown consumers: ${unknownConsumers.sorted().joinToString()}")
                val key = "$service/$containerPort/$protocol"
                if (!endpointKeys.add(key)) fail("duplicate cross-domain endpoint $key")
                if (!endpointPorts.add(protocol to hostPort)) fail("duplicate cross-domain host port $protocol/$hostPort")
                CrossDomainEndpointPolicy(service, containerPort, hostPort, protocol, consumers)
            }
        }
    }
    val unitPrefix = podman.path("unit_prefix").asText("webservices")
    if (unitPrefix != "webservices" && !unitPrefix.matches(Regex("p0test-[a-z0-9-]{1,24}"))) {
        fail("podman.unit_prefix must be a dedicated p0test namespace")
    }
    val rootfulStateRoot = podman.path("rootful_state_root").asText("/var/lib/webservices")
    if (standaloneHost(manifest)) {
        if (rootfulStateRoot != manifest.path("installerStateRoot").asText("/var/lib/webservices") ||
            (rootfulStateRoot != "/var/lib/webservices" &&
             !rootfulStateRoot.matches(Regex("/var/lib/stack-[a-z0-9-]{1,48}")))) {
            fail("standalone installerStateRoot must bind a dedicated native metadata root")
        }
    } else {
        if (rootfulStateRoot != "/var/lib/webservices" &&
            !rootfulStateRoot.matches(Regex("/var/lib/p0test-[a-z0-9-]{1,24}"))) {
            fail("podman.rootful_state_root must be a dedicated /var/lib/p0test namespace")
        }
        if ((unitPrefix == "webservices") != (rootfulStateRoot == "/var/lib/webservices")) {
            fail("podman isolated unit and state roots must be selected together")
        }
    }
    val rootfulGraphRoot = podman.path("rootful_graph_root").textOrNull()
    val rootfulRunRoot = podman.path("rootful_run_root").textOrNull()
    val mapNode = podman.path("port_map")
    val portMap = if (mapNode.isMissingNode) emptyMap() else {
        if (!mapNode.isObject) fail("podman.port_map must map canonical old host ports to isolated ports")
        mapNode.fieldsMap().associate { (key, value) ->
            if (!key.matches(Regex("[1-9][0-9]{0,4}")) || !value.isIntegralNumber ||
                key.toInt() !in 1..65535 || value.asInt() !in 1024..65535) fail("invalid isolated port identity")
            key.toInt() to value.asInt()
        }
    }
    if (unitPrefix == "webservices") {
        if (portMap.isNotEmpty()) fail("native/legacy published ports cannot be redirected alone")
        if (standaloneHost(manifest) && (rootfulGraphRoot != null || rootfulRunRoot != null)) {
            if (!rootfulStateRoot.matches(Regex("/var/lib/stack-[a-z0-9-]{1,48}")) ||
                rootfulGraphRoot != "$rootfulStateRoot/rootful-store/graph" ||
                rootfulRunRoot != "/run/${Path(rootfulStateRoot).fileName}-podman") {
                fail("native Root engine requires exact private metadata graph and dedicated run roots")
            }
        } else if (rootfulGraphRoot != null || rootfulRunRoot != null) {
            fail("legacy Podman authorities cannot be redirected alone")
        }
    } else if (rootfulGraphRoot == null || rootfulRunRoot != "/run/$unitPrefix-podman" ||
        !rootfulGraphRoot.matches(Regex("/mnt/stack/p0-existing-host-venue-[a-z0-9-]{1,24}/rootful-graph"))) {
        fail("isolated rootful graph and run roots must be explicit and dedicated")
    }
    val venueParent = rootfulGraphRoot?.removeSuffix("/rootful-graph")
    val venueVolumeRoot = siteConfig.path("storage").path("volume_root").textOrNull()
    val venuePgSsdRoot = siteConfig.path("storage").path("pg_ssd_root").textOrNull()
    val venueVectorDbsRoot = siteConfig.path("storage").path("vector_dbs").textOrNull()
    val venueControlSocketRoot = podman.path("control_socket_root").textOrNull()
    val venueLogRoot = podman.path("log_root").textOrNull()
    if (unitPrefix == "webservices") {
        if (venueControlSocketRoot != null || venueLogRoot != null) fail("legacy control and log roots cannot be redirected alone")
    } else if (venueVolumeRoot != "$venueParent/volumes" || venuePgSsdRoot != "$venueParent/pg-ssd" ||
        venueVectorDbsRoot != "$venueParent/vector-dbs" || venueControlSocketRoot != "/run/$unitPrefix-control" ||
        venueLogRoot != "/var/log/$unitPrefix") {
        fail("isolated storage, control-socket and log roots must be explicit and exclusive")
    }
    if (unitPrefix != "webservices" && (portMap.size != 50 ||
        portMap.keys.intersect(portMap.values.toSet()).isNotEmpty() ||
        portMap.values.toSet().size != 50 ||
        !portMap.keys.containsAll(setOf(80, 443, 9100, 7880, 7881, 7882)) ||
        siteConfig.path("runtime").path("livekit_node_ip").asText() != "192.168.140.1")) {
        fail("isolated port map and private Livekit ICE identity must name 50 distinct original and proposed identities")
    }
    return PodmanPolicy(
        rootfulModules,
        rootfulServices,
        domains,
        serviceDomains,
        crossDomainEndpoints.map { endpoint ->
            endpoint.copy(hostPort = if (unitPrefix == "webservices") endpoint.hostPort else
                portMap[endpoint.hostPort] ?: fail("missing isolated cross-domain port ${endpoint.hostPort}"))
        },
        podman.path("maintenance_root").asText("/mnt/lab_debian/stack_lab/stack_work"),
        resourceLimit(podman.path("resource_defaults").path("memory"), "memory"),
        resourceLimit(podman.path("resource_defaults").path("cpus"), "cpus"),
        unitPrefix,
        rootfulStateRoot,
        rootfulGraphRoot,
        rootfulRunRoot,
        portMap,
        venueVolumeRoot,
        venuePgSsdRoot,
        venueVectorDbsRoot,
        venueControlSocketRoot,
        venueLogRoot,
        standaloneHost(manifest)
    )
}

fun applyVenueBindPolicy(ir: ObjectNode, policy: PodmanPolicy) {
    if (policy.unitPrefix == "webservices") return
    val ci = policy.domains.singleOrNull { it.name == "ci-runner" } ?: fail("missing venue CI domain")
    val tests = policy.domains.singleOrNull { it.name == "test-runners" } ?: fail("missing venue test domain")
    val ca = ir.path("volumes").path("caddy_ca").path("hostPath").textOrNull()
        ?: fail("missing venue CA volume")
    if (ca != policy.venueVolumeRoot + "/caddy_ca") fail("venue CA volume differs from storage root")
    val sources = mapOf(
        "/mnt/stack/forgejo-runner-ssh" to "${ci.stateRoot}/forgejo-runner-ssh",
        "/mnt/stack/podman/test-runners/state/test-runner/results" to "${tests.stateRoot}/test-runner/results",
        "/mnt/stack/volumes/caddy_ca/caddy-ca.crt" to "$ca/caddy-ca.crt",
        "/run/p0-control" to (policy.venueControlSocketRoot ?: fail("missing venue control socket")),
        "/var/log/webservices/caddy" to "${policy.venueLogRoot}/caddy"
    )
    val counts = sources.keys.associateWith { 0 }.toMutableMap()
    ir.path("services").fieldsMap().forEach { (_, service) ->
        val mounts = service.path("volumes")
        if (mounts !is ArrayNode) return@forEach
        for (index in 0 until mounts.size()) {
            val mount = mounts[index]
            val source = if (mount.isTextual) mount.asText().substringBefore(':') else mount.path("source").asText()
            val replacement = sources[source] ?: continue
            counts[source] = counts.getValue(source) + 1
            if (mount.isTextual) mounts.set(index, nodes.textNode(replacement + mount.asText().removePrefix(source)))
            else (mount as? ObjectNode ?: fail("unsupported venue mount authority")).put("source", replacement)
        }
    }
    if (counts.values.any { it == 0 }) fail("expected isolated venue bind input is missing")
    val caddyProbe = ir.path("services").path("caddy").path("health").path("test")
    if (caddyProbe !is ArrayNode || caddyProbe.size() != 2 || caddyProbe[0].asText() != "CMD-SHELL")
        fail("isolated Caddy requires its declared shell health contract")
    caddyProbe.set(1, nodes.textNode(isolatedCaddyProbe(caddyProbe[1].asText())))
}

fun applyResourceDefaults(ir: ObjectNode, policy: PodmanPolicy) {
    ir.path("services").fieldsMap().forEach { (_, raw) ->
        val service = raw as ObjectNode
        val resources = service.withObject("resources")
        val limits = resources.withObject("limits")
        if (!limits.has("memory")) policy.defaultMemory?.let { limits.put("memory", it) }
        if (!limits.has("cpus")) policy.defaultCpus?.let { limits.put("cpus", it) }
    }
}

fun rewriteEndpointText(value: String, provider: String, containerPort: Int, hostPort: Int): String {
    return value.replace(
        Regex("(?<![a-zA-Z0-9_-])${Regex.escape(provider)}:${containerPort}(?![0-9])"),
        "host.containers.internal:$hostPort"
    )
}

fun rewriteEndpointConfigText(value: String, provider: String, containerPort: Int, hostPort: Int): String {
    val pairedPort = Regex(
        "(?is)((?:host|hostname|db_host|postgres_host)\\s*[:=]\\s*[\\\"']?${Regex.escape(provider)}[\\\"']?.{0,160}?(?:port|db_port|postgres_port)\\s*[:=]\\s*[\\\"']?)${containerPort}(?![0-9])"
    ).replace(value) { match -> "${match.groupValues[1]}$hostPort" }
    return rewriteEndpointText(pairedPort, provider, containerPort, hostPort).replace(
        Regex("(?i)((?:host|hostname|db_host|postgres_host)\\s*[:=]\\s*[\\\"']?)${Regex.escape(provider)}(?![a-zA-Z0-9_-])")
    ) { match -> "${match.groupValues[1]}host.containers.internal" }
}

fun rewriteEndpointCommand(value: JsonNode, provider: String, containerPort: Int, hostPort: Int): JsonNode {
    val rewritten = rewriteEndpointTree(value, provider, containerPort, hostPort)
    fun replaceBare(text: String): String = text.replace(
        Regex("(?<![a-zA-Z0-9_.-])${Regex.escape(provider)}(?![a-zA-Z0-9_.-])"),
        "host.containers.internal"
    )
    return when {
        rewritten.isTextual -> nodes.textNode(replaceBare(rewritten.asText()))
        rewritten.isArray -> arr().also { output -> rewritten.forEach { child ->
            output.add(if (child.isTextual) nodes.textNode(replaceBare(child.asText())) else child)
        } }
        else -> rewritten
    }
}

fun rewriteEndpointTree(value: JsonNode, provider: String, containerPort: Int, hostPort: Int): JsonNode = when {
    value.isTextual -> nodes.textNode(rewriteEndpointText(value.asText(), provider, containerPort, hostPort))
    value.isArray -> arr().also { output -> value.forEach { output.add(rewriteEndpointTree(it, provider, containerPort, hostPort)) } }
    value.isObject -> obj().also { output -> value.fieldsMap().forEach { (key, child) ->
        output.set<JsonNode>(key, rewriteEndpointTree(child, provider, containerPort, hostPort))
    } }
    else -> value.deepCopy()
}

fun applyCrossDomainEndpointPolicy(ir: ObjectNode, policy: PodmanPolicy) {
    val services = ir.path("services") as ObjectNode
    policy.crossDomainEndpoints.forEach { endpoint ->
        val provider = services.path(endpoint.service)
        if (provider.isMissingNode) fail("cross-domain endpoint names unknown service '${endpoint.service}'")
        val providerDomain = podmanDomainForService(provider).name
        if (providerDomain in endpoint.consumers) fail("cross-domain endpoint '${endpoint.service}' includes its provider domain '$providerDomain'")
        endpoint.consumers.forEach { consumerDomain ->
            if (consumerDomain != "rootful") {
                val allowed = policy.domains.first { it.name == consumerDomain }.allowDependencies
                if (providerDomain != "rootful" && providerDomain !in allowed) {
                    fail("endpoint consumer '$consumerDomain' does not allow provider domain '$providerDomain'")
                }
            }
            val consumers = services.fieldsMap().filter { (_, service) -> podmanDomainForService(service).name == consumerDomain }
            consumers.forEach consumerService@{ (_, rawService) ->
                val service = rawService as ObjectNode
                service.get("environment")?.let { current ->
                    service.set<JsonNode>("environment", rewriteEndpointTree(current, endpoint.service, endpoint.containerPort, endpoint.hostPort))
                }
                listOf("command", "entrypoint", "health").forEach { field ->
                    val current = service.get(field) ?: return@forEach
                    service.set<JsonNode>(field, rewriteEndpointCommand(current, endpoint.service, endpoint.containerPort, endpoint.hostPort))
                }
                val environment = service.path("environment") as? ObjectNode ?: return@consumerService
                environment.fieldsMap()
                    .filter { (key, value) -> key.endsWith("HOST") && value.asText() == endpoint.service }
                    .forEach { (key, _) -> environment.put(key, "host.containers.internal") }
                val hostKeys = environment.fieldsMap()
                    .filter { (key, value) -> key.endsWith("HOST") && value.asText() == "host.containers.internal" }
                    .map { it.first }
                hostKeys.forEach { hostKey ->
                    val portKey = hostKey.removeSuffix("HOST") + "PORT"
                    if (environment.has(portKey) && environment.path(portKey).asInt(-1) == endpoint.containerPort) {
                        environment.put(portKey, endpoint.hostPort)
                    }
                }
            }
        }
    }
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

fun gitRevision(dir: Path): String? {
    val process = ProcessBuilder("git", "rev-parse", "--verify", "HEAD")
        .directory(dir.toFile()).redirectErrorStream(true).start()
    val output = process.inputStream.bufferedReader().readText().trim()
    return if (process.waitFor() == 0 && output.matches(Regex("[0-9a-f]{40}"))) output else null
}

fun gitDirty(dir: Path): Boolean? {
    val process = ProcessBuilder("git", "status", "--porcelain", "--untracked-files=normal")
        .directory(dir.toFile()).redirectErrorStream(true).start()
    val output = process.inputStream.bufferedReader().readText()
    return if (process.waitFor() == 0) output.isNotBlank() else null
}

fun nativeAcceptanceImagePins(manifestPath: Path): Pair<Path, ObjectNode>? {
    val manifest = readTree(manifestPath)
    if (!manifest.has("nativeAcceptanceImagePinsPath")) return null
    val relative = manifest.path("nativeAcceptanceImagePinsPath")
    if (!relative.isTextual || relative.asText() != "global.settings/native-retained-acceptance-image.json")
        fail("native acceptance image pins require exact site-owned input path")
    val path = manifestPath.parent.resolve(relative.asText())
    if (!path.isRegularFile() || path.isSymbolicLink() || path.parent.isSymbolicLink()
        || !path.toRealPath().startsWith(manifestPath.parent.toRealPath()) || Files.size(path) > 32768)
        fail("missing, linked or oversized native acceptance image pins")
    val pins = readTree(path)
    fun keys(value: JsonNode, expected: Set<String>) =
        value.isObject && value.fieldNames().asSequence().toSet() == expected
    val digest = Regex("[a-f0-9]{64}")
    val image = Regex("sha256:[a-f0-9]{64}")
    if (!keys(pins, setOf("schemaVersion", "purpose", "image", "platform", "archiveFilename",
            "archiveSha256", "archiveBytes", "sourceModule", "containerfileSha256", "immutableParents"))
        || !pins.path("schemaVersion").isIntegralNumber || !pins.path("schemaVersion").canConvertToInt()
        || pins.path("schemaVersion").asInt() != 1
        || pins.path("purpose").asText() != "optional native retained-acceptance tooling; no managed runtime service"
        || !image.matches(pins.path("image").asText()) || pins.path("platform").asText() != "linux/amd64"
        || !Regex("[A-Za-z0-9][A-Za-z0-9._-]{0,199}\\.tar").matches(pins.path("archiveFilename").asText())
        || !pins.path("archiveSha256").isTextual || !digest.matches(pins.path("archiveSha256").asText())
        || !pins.path("archiveBytes").isIntegralNumber || !pins.path("archiveBytes").canConvertToLong()
        || pins.path("archiveBytes").asLong() !in 1L..(16L * 1024 * 1024 * 1024)
        || !pins.path("containerfileSha256").isTextual || !digest.matches(pins.path("containerfileSha256").asText()))
        fail("invalid immutable native acceptance image archive identity")
    val module = pins.path("sourceModule")
    if (!keys(module, setOf("id", "git", "commit")) || module.path("id").asText() != "test-runners"
        || !Regex("https://github\\.com/[A-Za-z0-9._-]+/[A-Za-z0-9._-]+").matches(module.path("git").asText())
        || !module.path("commit").isTextual || !Regex("[a-f0-9]{40}").matches(module.path("commit").asText()))
        fail("invalid native acceptance image source binding")
    val parents = pins.path("immutableParents")
    if (!parents.isArray || parents.size() != 2 || parents.any { parent ->
            !keys(parent, setOf("sourceReference", "immutableReference", "imageConfigId"))
            || !parent.path("sourceReference").isTextual || parent.path("sourceReference").asText().isBlank()
            || !Regex("[a-z0-9][a-z0-9._:/-]+@sha256:[a-f0-9]{64}").matches(parent.path("immutableReference").asText())
            || !parent.path("imageConfigId").isTextual || !Regex("(sha256:)?[a-f0-9]{64}").matches(parent.path("imageConfigId").asText())
        } || parents.map { it.path("immutableReference").asText() }.toSet().size != 2)
        fail("invalid immutable native acceptance image parent identities")
    return path to pins
}

fun sourceProvenance(manifest: Path, modules: List<ModuleCheckout>): ObjectNode {
    val generatorRoot = System.getenv("STACK_GENERATOR_ROOT")?.let(Path::of)?.toAbsolutePath()?.normalize()
        ?: fail("STACK_GENERATOR_ROOT is not set")
    val manifestTree = readTree(manifest)
    val provenance = obj().put("schemaVersion", 1)
    provenance.put("manifestSha256", sha256(manifest))
    val stackConfig = manifestTree.path("stackConfig").textOrNull()
    if (stackConfig != null) {
        val path = manifest.parent.resolve(stackConfig).normalize()
        if (!path.startsWith(manifest.parent) || !path.isRegularFile()) fail("invalid site stackConfig path: $stackConfig")
        provenance.put("stackConfigSha256", sha256(path))
    }
    val secretStore = manifestTree.path("secretStore").textOrNull()
    if (secretStore != null) {
        val path = manifest.parent.resolve(secretStore).normalize()
        if (!path.startsWith(manifest.parent) || !path.isRegularFile()) fail("invalid site secretStore path: $secretStore")
        provenance.put("secretStoreSha256", sha256(path))
    }
    nativeAcceptanceImagePins(manifest)?.let { (path, pins) ->
        val module = modules.singleOrNull { it.id == pins.path("sourceModule").path("id").asText() }
            ?: fail("native acceptance image source module is not selected")
        if (module.commit != pins.path("sourceModule").path("commit").asText()
            || module.remote != pins.path("sourceModule").path("git").asText()
            || sha256(module.dir.resolve("stack.containers/test-runner/Containerfile")) != pins.path("containerfileSha256").asText())
            fail("native acceptance image pins differ from selected source module or recipe")
        provenance.put("nativeAcceptanceImagePinsSha256", sha256(path))
    }
    provenance.put("generatorCommit", gitRevision(generatorRoot))
    provenance.put("generatorDirty", gitDirty(generatorRoot))
    provenance.put("siteCommit", gitRevision(manifest.parent))
    provenance.put("siteDirty", gitDirty(manifest.parent))
    val moduleRows = arr()
    modules.forEach { module ->
        moduleRows.add(obj().put("id", module.id).put("remote", module.remote)
            .put("commit", module.commit).put("dirty", gitDirty(module.dir)))
    }
    provenance.set<ArrayNode>("modules", moduleRows)
    return provenance
}

fun resolveModuleIntegrations(service: ObjectNode, selected: Set<String>) {
    val integrations = service.remove("moduleIntegrations") ?: return
    if (!integrations.isObject) fail("module integrations must be an object")
    integrations.fields().forEachRemaining { (module, patch) ->
        if (!module.matches(Regex("[a-z0-9][a-z0-9-]*")) || !patch.isObject ||
            patch.fieldNames().asSequence().toSet() != setOf("environment", "volumes") ||
            !patch.path("environment").isObject || !patch.path("volumes").isArray ||
            patch.path("environment").any { !it.isTextual } || patch.path("volumes").any { !it.isTextual })
            fail("module integration permits only literal environment and volume declarations")
        val environment = service.path("environment")
        if (!environment.isObject || !service.path("volumes").isArray ||
            patch.path("environment").fieldNames().asSequence().any { environment.has(it) } ||
            patch.path("volumes").any { incoming -> service.path("volumes").any { it == incoming } })
            fail("module integration conflicts with base service declarations")
        if (module in selected) {
            val mergedEnvironment = service.get("environment") as ObjectNode
            patch.path("environment").fields().forEachRemaining { (key, value) ->
                if (mergedEnvironment.has(key)) fail("module integrations conflict")
                mergedEnvironment.set<JsonNode>(key, value.deepCopy())
            }
            val mergedVolumes = service.get("volumes") as ArrayNode
            patch.path("volumes").forEach { value ->
                if (mergedVolumes.any { it == value }) fail("module integrations conflict")
                mergedVolumes.add(value.deepCopy<JsonNode>())
            }
        }
    }
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
            resolveModuleIntegrations(service, requested.toSet())
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

fun quadletManaged(service: JsonNode): Boolean =
    service.path("lifecycle").asText() != "on-demand" || service.path("quadletManaged").asBoolean(false)

fun quadletEmitted(service: JsonNode): Boolean =
    quadletManaged(service) || (activePodmanPolicy.standalone && service.has("build"))

fun freezeLocalBuildImages(ir: ObjectNode, manifestPath: Path) {
    val services = ir.path("services") as ObjectNode
    if (services.fieldsMap().any { (_, service) -> service.has("frozenBuildImage") })
        fail("frozenBuildImage is generator-owned, not a module override")
    val manifest = readTree(manifestPath)
    if (!manifest.has("localBuildImagePinsPath")) return
    val relative = manifest.path("localBuildImagePinsPath")
    if (!relative.isTextual || relative.asText() != "global.settings/local-build-image-ids.json")
        fail("local build identities require exact site-owned global.settings/local-build-image-ids.json")
    val source = manifestPath.parent.resolve(relative.asText())
    if (!source.isRegularFile() || source.isSymbolicLink() ||
        !source.toRealPath().startsWith(manifestPath.parent.toRealPath()))
        fail("local build identity pins are missing or linked outside site")
    val pins = readTree(source)
    if (pins.fieldsMap().map { it.first }.toSet() != setOf("schemaVersion", "images") ||
        !pins.path("schemaVersion").isInt || pins.path("schemaVersion").asInt() != 1 ||
        !pins.path("images").isObject)
        fail("invalid local build identity pins schema")
    val builds = services.fieldsMap().filter { (_, service) -> service.has("build") && quadletEmitted(service) }
        .map { it.first }.toSet()
    val images = pins.path("images").fieldsMap().associate { (name, value) ->
        if (!value.isTextual || !value.asText().matches(Regex("sha256:[0-9a-f]{64}")))
            fail("local build identity must be an immutable configuration ID: $name")
        name to value.asText()
    }
    if (builds.isEmpty() || images.keys != builds)
        fail("local build identities must cover every selected Quadlet build exactly, without extras")
    val tags = images.mapKeys { (name, _) -> "localhost/webservices/$name:bundle" }
    services.fieldsMap().forEach { (name, raw) ->
        val service = raw as ObjectNode
        val digest = if (service.has("build")) images[name] else tags[service.path("image").asText()]
        if (digest != null) {
            service.put("image", digest)
            service.put("updatePolicy", "pinned")
            service.put("frozenBuildImage", digest)
        } else if (!service.has("build") && service.path("image").asText().startsWith("localhost/webservices/")) {
            fail("unresolved local build image consumer: $name")
        }
    }
    ir.put("quadletBuildImagesFrozen", true)
}

fun immutableOverlayFiles(module: ModuleCheckout, relative: Path): List<Triple<Path, String, Boolean>> {
    if (relative.isAbsolute || relative.normalize() != relative || relative.any { it.toString() == ".." })
        fail("noncanonical overlay in '${module.id}'")
    // Read the reviewed Git tree, NOT the worktree. Ignored/private files and
    // interpreter caches are never traversed; source links are rejected before
    // any target content can be dereferenced/copied into a release.
    val tree = commandOutput(listOf("git", "ls-tree", "-r", "-z", module.commit, "--", relative.toString()), module.dir)
    val rows = tree.split('\u0000').filter(String::isNotEmpty)
    if (rows.isEmpty()) fail("missing tracked overlay in '${module.id}'")
    return rows.map { row ->
        val fields = row.split('\t', limit = 2)
        val header = fields.first().split(' ')
        if (fields.size != 2 || header.size != 3 || header[0] !in setOf("100644", "100755") || header[1] != "blob" ||
            !header[2].matches(Regex("[a-f0-9]{40,64}"))) fail("linked/special overlay in '${module.id}'")
        val path = Path(fields[1])
        if (path.isAbsolute || path.normalize() != path || !path.startsWith(relative))
            fail("escaping overlay in '${module.id}'")
        Triple(path, header[2], header[0] == "100755")
    }
}

fun overlayBlob(module: ModuleCheckout, objectId: String): ByteArray {
    val process = ProcessBuilder("git", "cat-file", "blob", objectId).directory(module.dir.toFile()).start()
    val data = process.inputStream.readNBytes(64 * 1024 * 1024 + 1)
    if (data.size > 64 * 1024 * 1024) { process.destroyForcibly(); fail("oversized module overlay") }
    if (!process.waitFor(30, java.util.concurrent.TimeUnit.SECONDS) || process.exitValue() != 0) {
        process.destroyForcibly(); fail("cannot read reviewed overlay object in '${module.id}'")
    }
    return data
}

fun materializeModules(modules: List<ModuleCheckout>, output: Path) {
    val owners = mutableMapOf<Path, String>()
    modules.forEach { module ->
        module.metadata.path("overlays").forEach { overlayNode ->
            val relative = Path(overlayNode.asText())
            if (relative.startsWith("runtime.overlays") || relative.fileName.toString() == "stack.runtime.yaml") return@forEach
            immutableOverlayFiles(module, relative).forEach { (sourceRelative, blob, executable) ->
                val content = overlayBlob(module, blob)
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
                Files.write(destination, content, java.nio.file.StandardOpenOption.CREATE_NEW)
                Files.setPosixFilePermissions(destination, java.nio.file.attribute.PosixFilePermissions.fromString(if (executable) "rwxr-xr-x" else "rw-r--r--"))
                if (destinationRelative.startsWith(Path("stack.config"))) {
                    val configRelative = Path("runtime/configs").resolve(Path("stack.config").relativize(destinationRelative))
                    val runtimeDestination = output.resolve(configRelative).normalize()
                    owners.put(runtimeDestination, module.id)?.let { fail("overlay collision at $runtimeDestination between '$it' and '${module.id}'") }
                    runtimeDestination.parent.createDirectories()
                    Files.write(runtimeDestination, content, java.nio.file.StandardOpenOption.CREATE_NEW)
                    Files.setPosixFilePermissions(runtimeDestination, java.nio.file.attribute.PosixFilePermissions.fromString(if (executable) "rwxr-xr-x" else "rw-r--r--"))
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
    val forbidden = excludedIds(manifest, "excludedComponents")
    requested.firstOrNull { it in forbidden }?.let { fail("site manifest selects excluded component '$it'") }

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
            if (dependency in forbidden) fail("component '$component' reintroduces excluded component '$dependency'")
            if (!components.has(dependency)) fail("component '$component' depends on unknown component '$dependency'")
            if (selected.add(dependency)) queue.add(dependency)
        }
    }
    return components.fieldNames().asSequence().filter { selected.contains(it) }.toList()
}

fun materializeComponentLock(manifestPath: Path, output: Path, ir: ObjectNode) {
    val manifest = readTree(manifestPath)
    val moduleIds = ir.path("modules").map { it.path("id").asText() }
    val forbidden = excludedIds(manifest, "excludedComponents")
    moduleIds.firstOrNull { it in forbidden }?.let { fail("module reintroduces excluded component '$it'") }
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

fun standaloneHost(manifest: JsonNode): Boolean {
    val mode = manifest.path("deploymentMode")
    if (mode.isMissingNode) return false // Preserve the existing managed contract.
    if (!mode.isTextual || mode.asText() != "standalone") fail("unknown deploymentMode")
    if (manifest.has("agentVmSpec")) fail("standalone deployment cannot manage an agent VM")
    val scope = manifest.path("storageScope")
    val root = scope.path("root").asText()
    if (!scope.isObject || scope.fieldNames().asSequence().toSet() != setOf("root", "dataClass") ||
        scope.path("dataClass").asText() !in setOf("synthetic", "production") ||
        !root.matches(Regex("/[A-Za-z0-9_./-]+")) || root == "/" || Path(root).normalize().toString() != root)
        fail("standalone deployment requires an explicit canonical storageScope and dataClass")
    return true
}

fun standaloneCaddyLogRoot(): String =
    (activePodmanPolicy.venueVolumeRoot ?: fail("standalone logging requires a declared volume root")).trimEnd('/') + "/_logs/caddy"

fun storageMarkerPythonJson(node: JsonNode): String = when {
    node.isObject -> node.fieldsMap().sortedBy { it.first }.joinToString(", ", "{", "}") { (key, value) -> json.writeValueAsString(key) + ": " + storageMarkerPythonJson(value) }
    node.isArray -> node.joinToString(", ", "[", "]") { storageMarkerPythonJson(it) }
    node.isTextual || node.isIntegralNumber || node.isBoolean || node.isNull -> json.writeValueAsString(node)
    else -> fail("unsupported native storage marker value")
}

fun standaloneStorageMarkerSha(manifest: JsonNode): String {
    val domains = arr()
    val roots = sortedSetOf<String>()
    activePodmanPolicy.domains.sortedBy { it.name }.forEach { domain ->
        val row = obj().put("name", domain.name).put("user", domain.user)
            .put("uid", domain.uid ?: fail("native storage marker requires fixed domain UID"))
            .put("stateRoot", domain.stateRoot).put("graphRoot", domain.graphRoot).put("volumeRoot", domain.volumeRoot)
        domains.add(row); roots.addAll(listOf(domain.stateRoot, domain.graphRoot, domain.volumeRoot))
    }
    val record = obj().put("schemaVersion", 1).put("kind", "standalone-stack-storage").put("site", manifest.path("site").asText())
    record.set<JsonNode>("scope", manifest.path("storageScope").deepCopy<JsonNode>())
    record.set<ArrayNode>("domains", domains); record.set<ArrayNode>("roots", arr().addAll(roots.map(nodes::textNode)))
    return MessageDigest.getInstance("SHA-256").digest((storageMarkerPythonJson(record) + "\n").toByteArray(Charsets.UTF_8))
        .joinToString("") { "%02x".format(it) }
}

// Root-selected non-client peers are topology, never inferred identities. The
// Caddy adapter separately validates overlap with its trusted-proxy inventory.
fun standaloneResultsMount(name: String, service: ObjectNode, scopeRoot: Path): String? {
    val dynamic = "\${TEST_RESULTS_HOST_DIR:?TEST_RESULTS_HOST_DIR must be set by run-tests.sh}"
    val target = "/app/test-results"
    val marker = service.path("x-standalone-results-mount")
    val candidates = service.path("volumes").filter { mount ->
        if (mount.isTextual) mount.asText().contains("TEST_RESULTS_HOST_DIR") || mount.asText().contains(target)
        else mount.path("source").asText().contains("TEST_RESULTS_HOST_DIR") || mount.path("target").asText() == target
    }
    if (marker.isMissingNode && candidates.isEmpty() && name !in setOf("test-runner", "test-runner-managed")) return null
    if (name !in setOf("test-runner", "test-runner-managed") || service.path("module").asText() != "test-runners" ||
        service.path("lifecycle").asText() != "on-demand" || service.path("placement").asText() != "rootless" ||
        service.path("rootlessDomain").asText() != "test-runners") fail("unreviewed standalone results service/domain")
    if (!marker.isObject || marker.fieldNames().asSequence().toSet() != setOf("version", "target") ||
        !marker.path("version").isInt || marker.path("version").asInt() != 1 || marker.path("target").asText() != target)
        fail("standalone results requires the exact owning-module mount marker")
    val mount = candidates.singleOrNull() ?: fail("standalone results requires one exact structured bind")
    if (!mount.isObject || mount.fieldNames().asSequence().toSet() != setOf("type", "source", "target") ||
        mount.path("type").asText() != "bind" || mount.path("source").asText() != dynamic || mount.path("target").asText() != target)
        fail("standalone results bind contract differs")
    val domain = activePodmanPolicy.domains.singleOrNull { it.name == "test-runners" }
        ?: fail("standalone results requires its selected native domain")
    val root = Path(domain.volumeRoot)
    if (domain.uid != 786 || domain.user != "webservices-lab-test-runners" || "test-runners" !in domain.modules ||
        service.path("rootlessUser").asText() != domain.user || service.path("rootlessVolumeRoot").asText() != domain.volumeRoot ||
        !domain.volumeRoot.matches(Regex("/[A-Za-z0-9_./-]+")) || !root.isAbsolute || root.normalize().toString() != domain.volumeRoot || !root.startsWith(scopeRoot) || root == scopeRoot ||
        domain.volumeRoot.contains('$') || domain.volumeRoot.contains(':') || domain.volumeRoot.contains('\n'))
        fail("standalone results requires the admitted canonical actor volume root")
    // Keep the existing pwuser runner, but map its UID/GID to actor 786.
    // The actor-created 0700 leaf needs neither :U nor ownership repair.
    if (service.has("userns") || service.has("user") || service.path("environment").has("TEST_RUNNER_STANDALONE_RESULTS"))
        fail("standalone results ownership contract cannot be overridden")
    service.put("userns", "keep-id:uid=1000,gid=1000")
    // keep-id otherwise selects the mapped user before image-only CA bootstrap.
    service.put("user", "0:0")
    service.withObject("environment").put("TEST_RUNNER_STANDALONE_RESULTS", "v1")
    return "$root/test-results"
}

fun standaloneIngressDirectPeers(manifest: JsonNode): List<String> {
    val selected = manifest.path("ingressDirectNonClientCidrs")
    if (selected.isMissingNode) return emptyList()
    if (!selected.isArray || selected.size() > 64) fail("invalid ingressDirectNonClientCidrs inventory")
    val result = selected.map { value ->
        if (!value.isTextual) fail("non-text ingress direct peer CIDR")
        val text = value.asText()
        val parts = text.split('/')
        if (parts.size != 2 || !parts[0].matches(Regex("[0-9a-f:.]+"))) fail("invalid ingress direct peer CIDR")
        val bits = parts[1].toIntOrNull() ?: fail("invalid ingress direct peer prefix")
        if (parts[1] != bits.toString()) fail("noncanonical ingress direct peer prefix")
        val ipv6 = ':' in parts[0]
        val bytes = if (ipv6) {
            // A colon and this numeric-only grammar prevent DNS resolution.
            try { java.net.InetAddress.getByName(parts[0]).address.map { it.toInt() and 255 } }
            catch (_: Exception) { fail("invalid IPv6 ingress direct peer") }
        } else {
            val octets = parts[0].split('.')
            if (octets.size != 4) fail("invalid IPv4 ingress direct peer")
            octets.map { val n = it.toIntOrNull() ?: fail("invalid IPv4 ingress direct peer")
                if (n !in 0..255 || it != n.toString()) fail("noncanonical IPv4 ingress direct peer")
                n }
        }
        val width = if (ipv6) 128 else 32
        if (bytes.size != width / 8 || bits !in 0..width) fail("invalid ingress direct peer family/prefix")
        if ((bits until width).any { bit -> (bytes[bit / 8] and (1 shl (7 - bit % 8))) != 0 })
            fail("ingress direct peer CIDR has host bits")
        val privatePeer = if (ipv6) {
            ((bytes[0] and 254) == 252 && bits >= 7) ||
                (bits == 128 && bytes.dropLast(1).all { it == 0 } && bytes.last() == 1)
        } else (bytes[0] == 10 && bits >= 8) || (bytes[0] == 127 && bits >= 8) ||
            (bytes[0] == 172 && bytes[1] in 16..31 && bits >= 12) ||
            (bytes[0] == 192 && bytes[1] == 168 && bits >= 16)
        if (!privatePeer) fail("ingress non-client inventory must be wholly private/loopback")
        if (ipv6) {
            val words = (0 until 8).map { (bytes[2 * it] shl 8) or bytes[2 * it + 1] }
            var start = -1; var length = 1; var i = 0
            while (i < words.size) {
                if (words[i] != 0) { i++; continue }
                var end = i; while (end < words.size && words[end] == 0) end++
                if (end - i > length) { start = i; length = end - i }
                i = end
            }
            val canonical = if (start < 0) words.joinToString(":") { it.toString(16) }
                else words.take(start).joinToString(":") { it.toString(16) } + "::" +
                    words.drop(start + length).joinToString(":") { it.toString(16) }
            if (parts[0] != canonical) fail("noncanonical IPv6 ingress direct peer")
        }
        text
    }
    if (result.distinct().size != result.size) fail("duplicate ingress direct peer CIDR")
    return result
}

fun applyStandaloneHostProfile(ir: ObjectNode, manifest: JsonNode) {
    if (!standaloneHost(manifest)) return
    if (activePodmanPolicy.unitPrefix != "webservices") fail("standalone deployment requires the ordinary native host profile")
    val scopeRoot = Path(manifest.path("storageScope").path("root").asText())
    val ingressDirectPeers = standaloneIngressDirectPeers(manifest)
    fun requireScoped(root: String) {
        val path = Path(root).normalize()
        if (!path.startsWith(scopeRoot) || path == scopeRoot) fail("standalone private storage escapes its declared scope")
    }
    activePodmanPolicy.domains.forEach { listOf(it.stateRoot, it.graphRoot, it.volumeRoot).forEach(::requireScoped) }
    ir.path("volumes").fieldsMap().forEach { (_, volume) -> volume.path("hostPath").textOrNull()?.let(::requireScoped) }
    ir.path("services").fieldsMap().forEach { (name, raw) ->
        val service = raw as ObjectNode
        val resultsSource = standaloneResultsMount(name, service, scopeRoot)
        if (name == "volume-init") {
            val check = service.path("x-standalone-storage-check")
            if (service.path("placement").asText() != "rootful" || check.path("version").asInt() != 1 ||
                !check.path("entrypoint").isArray || !check.path("command").isArray)
                fail("standalone requires owning-module native storage verification contract")
            // Native scoped preparation owns directory creation/permissions.
            // Retain the selected oneshot as an exact read-only scope proof,
            // never give it a parent of the private Caddy signing store.
            service.set<ArrayNode>("volumes", arr().add("$scopeRoot/.stack-installation.json:/scope-marker.json:ro"))
            service.set<JsonNode>("entrypoint", check.path("entrypoint").deepCopy<JsonNode>())
            service.set<JsonNode>("command", check.path("command").deepCopy<JsonNode>())
            service.set<ObjectNode>("environment", obj().put("STACK_STORAGE_MARKER_SHA256", standaloneStorageMarkerSha(manifest)))
            service.put("readOnly", true); service.set<ArrayNode>("capDrop", arr().add("ALL"))
            service.set<ArrayNode>("securityOpt", arr().add("no-new-privileges:true"))
            service.put("storageProvisioningOwner", "native-installer")
        }
        if (name == "caddy") {
            // Literal sealed IR input, not an ambient or master-secret override.
            service.withObject("environment").put("P0_INGRESS_DIRECT_NON_CLIENT_CIDRS", ingressDirectPeers.joinToString(" "))
        }
        if (name == "alloy") {
            val uids = setOf(0) + activePodmanPolicy.domains.map { it.uid ?: fail("standalone journal scope requires fixed domain UIDs") }
            val alternatives = ir.path("services").fieldsMap().sortedBy { it.first }
                .filter { (unit, _) -> !unit.contains("firefly") && unit != "postgres" }
                .map { (unit, selected) ->
                    if (!unit.matches(Regex("[a-z0-9][a-z0-9-]{0,95}"))) fail("invalid selected journal unit")
                    if (selected.path("placement").asText("rootful") == "rootful") "webservices-$unit[.]service;"
                    else "user@${activePodmanPolicy.domains.singleOrNull { it.name == selected.path("rootlessDomain").asText() }?.uid ?: fail("missing journal actor UID")}[.]service;webservices-$unit[.]service"
                }
            service.withObject("environment").put("STACK_LOG_UID_REGEX", uids.sorted().joinToString("|"))
                .put("STACK_LOG_UNIT_REGEX", alternatives.joinToString("|", "^(", ")$"))
        }
        val volumes = service.path("volumes")
        if (volumes.isArray) {
            val retained = arr()
            volumes.forEach { mount ->
                val source = if (mount.isTextual) mount.asText().substringBefore(':') else mount.path("source").asText()
                if (source == "/run/p0-control") {
                    if (name != "caddy" || !mount.isTextual || mount.asText() != "/run/p0-control:/run/p0-control:ro")
                        fail("unreviewed managed control mount in standalone profile")
                } else {
                    fun stateRoot(domain: String): String = activePodmanPolicy.domains.singleOrNull { it.name == domain }?.stateRoot
                        ?: fail("standalone bind requires selected domain '$domain'")
                    val replacement = when (source) {
                        "\${TEST_RESULTS_HOST_DIR:?TEST_RESULTS_HOST_DIR must be set by run-tests.sh}" ->
                            resultsSource ?: fail("unreviewed dynamic standalone results source")
                        "/var/log/webservices/caddy" -> standaloneCaddyLogRoot()
                        "/mnt/stack/forgejo-runner-ssh" -> stateRoot("ci-runner") + "/forgejo-runner-ssh"
                        "/mnt/stack/podman/test-runners/state/test-runner/results" -> stateRoot("test-runners") + "/test-runner/results"
                        "/mnt/stack/volumes/caddy_ca/caddy-ca.crt" ->
                            (ir.path("volumes").path("caddy_ca").path("hostPath").textOrNull()
                                ?: fail("standalone bind requires selected CA volume")) + "/caddy-ca.crt"
                        "/var/lib/webservices-rootless-test-runners/current/build" -> stateRoot("test-runners") + "/current/build"
                        "/var/lib/webservices-rootless-test-runners/current/site/components.lock.json" -> stateRoot("test-runners") + "/current/site/components.lock.json"
                        else -> source
                    }
                    if (replacement == source) retained.add(mount.deepCopy<JsonNode>())
                    else if (mount.isTextual) retained.add(replacement + mount.asText().removePrefix(source))
                    else retained.add(mount.deepCopy<ObjectNode>().put("source", replacement))
                }
            }
            service.set<ArrayNode>("volumes", retained)
        }
    }
    // These applications remain selected and must be tested, not silently deferred.
    ir.set<ArrayNode>("deferredCapabilities", arr())
}

fun requireStandaloneCaddyPrivacy(source: String, output: Path) {
    // A finite reviewed native source contract, NOT a format-name waiver or a
    // permissive Caddyfile parser. Any extra logger/import/block (even filtered)
    // changes this approved template and requires a new owning source review.
    // The native encoder serializes only schema/ts/level, never Zap message,
    // logger, request, error or contextual fields; standard access logs are off.
    val sourceSha = MessageDigest.getInstance("SHA-256").digest(source.toByteArray(Charsets.UTF_8))
        .joinToString("") { "%02x".format(it) }
    // Reviewed immutable-sub forwarding delta: clears caller identity before
    // shortcuts, strips integration identity, fixed issuer. No logger/encoder,
    // ingress guard, import or managed-control change; still ONE exact template.
    if (sourceSha != "cd5297dd239b573ea677539a61415a21cd0ed9d32917b064120ea640862775e6")
        fail("standalone ingress requires the reviewed metadata-only Caddy source")
    val plugin = output.resolve("build/stack.containers/caddy-ingress")
    listOf(output, output.resolve("build"), output.resolve("build/stack.containers"), plugin).forEach {
        if (!it.isDirectory() || it.isSymbolicLink()) fail("standalone native encoder source missing or linked")
    }
    val pins = mapOf(
        "encoder.go" to "59ba0d7348bcb51dbcc40bee81fbfcbbd8b76f59fa83a9461837fd2c257c8d3f",
        "Containerfile" to "2d9c533d78fabce12e2fa64d63104c7e6ab60d738d4192dd5bf4cb9948c23a2f",
        "SOURCES.sha256" to "b0438ee8b0f94ceea3ff47ed19229a567a1fd5aff3461bde708bcd1221e27faa"
    )
    pins.forEach { (name, digest) ->
        val path = plugin.resolve(name)
        if (!path.isRegularFile() || path.isSymbolicLink() || sha256(path) != digest)
            fail("standalone requires the reviewed native metadata encoder/build source")
    }
    // The pinned builder compiles this local module and checks both native
    // modules. Check its entire pinned source inventory here as well, so an
    // additional/mutated Go source cannot redefine the approved log behavior.
    val expected = mutableMapOf<String, String>()
    plugin.resolve("SOURCES.sha256").readLines().forEach { line ->
        val match = Regex("([a-f0-9]{64})  (\\./[A-Za-z0-9_./-]+)").matchEntire(line)
            ?: fail("invalid reviewed native encoder source inventory")
        val name = match.groupValues[2].removePrefix("./")
        val relative = Path(name)
        if (relative.isAbsolute || relative.normalize().toString() != name || relative.startsWith("..") ||
            expected.put(name, match.groupValues[1]) != null)
            fail("ambiguous reviewed native encoder source inventory")
    }
    val files = mutableSetOf<String>()
    Files.walk(plugin).use { paths -> paths.forEach { path ->
        if (path.isSymbolicLink()) fail("linked native encoder source")
        if (path.isRegularFile()) files += plugin.relativize(path).toString()
        else if (!path.isDirectory()) fail("special native encoder source")
    } }
    if (files != expected.keys + setOf("SOURCES.sha256", "build-recipe.json"))
        fail("additional or missing native encoder source")
    expected.forEach { (name, digest) ->
        if (sha256(plugin.resolve(name)) != digest) fail("native encoder source differs from reviewed inventory")
    }
}

fun materializeStandaloneHostInputs(manifest: ObjectNode, output: Path) {
    if (!standaloneHost(manifest)) return
    listOf("build/stack.config/caddy/Caddyfile", "runtime/configs/caddy/Caddyfile").forEach { relative ->
        val caddy = output.resolve(relative)
        if (!caddy.isRegularFile() || caddy.isSymbolicLink()) fail("standalone Caddy source missing")
        val start = "# webservices-component-start caddy"
        val end = "# webservices-component-end caddy"
        val source = caddy.readText()
        if (source.split(start).size != 2 || source.split(end).size != 2) fail("ambiguous managed-control Caddy block")
        requireStandaloneCaddyPrivacy(source, output)
        val before = source.substringBefore(start)
        val managed = source.substringAfter(start).substringBefore(end)
        if (!managed.contains("unix//run/p0-control/http.sock") || !managed.contains("control.{"))
            fail("unreviewed managed-control Caddy source")
        // This marked source block contains only the managed control and agent API routes.
        caddy.writeText(before + source.substringAfter(end))
    }
    if ("alloy" in selectedModuleIds(manifest)) {
        listOf("build/stack.config/alloy/alloy.hcl", "runtime/configs/alloy/alloy.hcl").forEach { relative ->
            val config = output.resolve(relative)
            if (!config.isRegularFile() || config.isSymbolicLink() ||
                !config.readText().contains("sys.env(\"STACK_LOG_UID_REGEX\")") ||
                !config.readText().contains("sys.env(\"STACK_LOG_UNIT_REGEX\")"))
                fail("standalone journal source lacks selected-UID/unit scope")
        }
    }
}

fun materializeSiteManifest(manifestPath: Path, output: Path) {
    nativeAcceptanceImagePins(manifestPath)
    val manifest = readTree(manifestPath)
    val siteDir = output.resolve("site")
    siteDir.createDirectories()
    manifestPath.copyTo(siteDir.resolve("manifest.json"), overwrite = true)
    if (!standaloneHost(manifest) && manifest.path("site").asText() == "latium" && manifest.path("agentVmSpec").asText() != "agent-vm.json")
        fail("Latium requires exact site-owned agent-vm.json")
    (listOf("stackConfig", "secretStore") + listOfNotNull(
        "imageIdentityPinsPath".takeIf { manifest.has(it) },
        "buildBaseIdentityPinsPath".takeIf { manifest.has(it) },
        "localBuildImagePinsPath".takeIf { manifest.has(it) },
        "nativeAcceptanceImagePinsPath".takeIf { manifest.has(it) },
        "agentVmSpec".takeIf { manifest.has(it) })).forEach { key ->
        val relative = manifest.path(key).textOrNull() ?: fail("site manifest missing $key")
        if (relative.startsWith("/")) fail("site manifest $key must be relative: $relative")
        val source = manifestPath.parent.resolve(relative).normalize()
        if (!source.isRegularFile() || source.isSymbolicLink() || !source.toRealPath().startsWith(manifestPath.parent.toRealPath()))
            fail("site manifest $key points to missing or linked file: $source")
        if (key == "buildBaseIdentityPinsPath" &&
            (relative != "global.settings/build-base-image-ids.json" ||
             (activePodmanPolicy.unitPrefix == "webservices" && !standaloneHost(manifest))))
            fail("only isolated venue may select exact build-base identity pins")
        if (key == "agentVmSpec") {
            val vm = readTree(source)
            val pins = vm.path("runtime")
            val ports = vm.path("servicePorts")
            if (activePodmanPolicy.unitPrefix != "webservices") {
                val mapping = activePodmanPolicy.portMap
                if (!vm.path("network").asText().matches(Regex("p0-venue-[a-z0-9-]{1,24}")) ||
                    vm.path("name").asText() != vm.path("network").asText() + "-agents" ||
                    vm.path("diskRoot").asText() != "/mnt/lab_debian/agent_vm/" + vm.path("name").asText() ||
                    !ports.isObject || ports.size() != 3 ||
                    !ports.path("https").isIntegralNumber || !ports.path("smtp").isIntegralNumber ||
                    !ports.path("imap").isIntegralNumber ||
                    ports.path("https").asInt(-1) != mapping[443] ||
                    ports.path("smtp").asInt(-1) != mapping[587] ||
                    ports.path("imap").asInt(-1) != mapping[993]) {
                    fail("isolated guest service ports/network differ from generated host venue")
                }
            } else if (!ports.isMissingNode) fail("legacy site cannot carry unreviewed guest port override")
            if (!vm.path("schemaVersion").isIntegralNumber || vm.path("schemaVersion").asInt() != 1
                || (activePodmanPolicy.unitPrefix == "webservices" && vm.path("name").asText() != "p0-agents")
                || vm.path("projectLanes") !is ArrayNode || vm.path("projectLanes").size() != 0
                || vm.path("gpuDevices") !is ArrayNode || vm.path("gpuDevices").size() != 0
                || !Regex("[a-f0-9]{40}").matches(pins.path("controlCommit").asText())
                || !Regex("[a-f0-9]{40}").matches(pins.path("worklaneCommit").asText())
                || !vm.path("vcpus").isIntegralNumber || vm.path("vcpus").asInt() != 8
                || !vm.path("memoryMiB").isIntegralNumber || vm.path("memoryMiB").asInt() != 12288
                || !vm.path("osGiB").isIntegralNumber || vm.path("osGiB").asInt() != 80
                || !vm.path("workGiB").isIntegralNumber || vm.path("workGiB").asInt() != 100
                || !vm.path("swapGiB").isIntegralNumber || vm.path("swapGiB").asInt() != 4)
                fail("invalid site-owned empty CPU agent VM pins")
        }
        val destination = siteDir.resolve(relative).normalize()
        if (!destination.startsWith(siteDir)) fail("site manifest $key escapes site dir: $relative")
        destination.parent.createDirectories()
        source.copyTo(destination, overwrite = true)
        if (key == "agentVmSpec") {
            writeJson(siteDir.resolve("agent-vm.provenance.json"), obj().put("schemaVersion", 1)
                .put("path", relative).put("sha256", sha256(source))
                .put("controlCommit", readTree(source).path("runtime").path("controlCommit").asText()))
        }
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
        "userns" to "userns_mode", "groupAdd" to "group_add", "pidMode" to "pid"
    ).forEach { (from, to) -> copyField(service, output, from, to) }
    (output.get("volumes") as? ArrayNode)?.let { volumes ->
        volumes.forEachIndexed { index, mount ->
            if (mount.isTextual && mount.asText().startsWith("%t/")) {
                volumes.set(index, nodes.textNode("\${XDG_RUNTIME_DIR}" + mount.asText().removePrefix("%t")))
            }
        }
    }
    service.get("build")?.takeUnless { service.has("frozenBuildImage") }?.let { raw ->
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

val rootfulDomain: PodmanDomain
    get() = PodmanDomain(
        name = "rootful",
        quadletDir = "quadlet/rootful",
        stateRoot = activePodmanPolicy.rootfulStateRoot,
        rootlessUser = null,
        envFilePrefix = "/run/${activePodmanPolicy.unitPrefix}",
        targetInstall = "multi-user.target",
        releaseRoot = "${activePodmanPolicy.rootfulStateRoot}/current",
        graphRoot = if (activePodmanPolicy.standalone) activePodmanPolicy.rootfulGraphRoot else null
    )

fun rootfulEngineConfigRoot(): String = activePodmanPolicy.rootfulStateRoot +
    if (activePodmanPolicy.standalone && activePodmanPolicy.rootfulGraphRoot != null) "/rootful-store" else ""

fun nativeRootfulEngineServiceLines(domain: PodmanDomain): List<String> =
    if (domain.name == "rootful" && activePodmanPolicy.standalone && activePodmanPolicy.rootfulGraphRoot != null)
        listOf("Environment=TMPDIR=${activePodmanPolicy.rootfulGraphRoot}",
            "Environment=HOME=${rootfulEngineConfigRoot()}",
            "Environment=XDG_CONFIG_HOME=${rootfulEngineConfigRoot()}/xdg",
            "Environment=XDG_RUNTIME_DIR=${activePodmanPolicy.rootfulRunRoot}",
            "Environment=REGISTRY_AUTH_FILE=${rootfulEngineConfigRoot()}/empty-auth.json",
            "UnsetEnvironment=CONTAINERS_CONF_OVERRIDE CONTAINERS_CONF_MODULES STORAGE_DRIVER STORAGE_OPTS CONTAINERS_STORAGE_OPTS CONTAINER_HOST CONTAINER_CONNECTION DOCKER_HOST",
            "ExecStartPre=/usr/bin/python3 -B ${domain.releaseRoot}/ops/install-pinned-images.py --bundle ${domain.releaseRoot} --validate-rootful-store --require-runtime")
    else emptyList()

val rootlessDomains: List<PodmanDomain>
    get() = activePodmanPolicy.domains.map {
        PodmanDomain(
            name = it.name,
            quadletDir = "quadlet/rootless-${it.name}",
            stateRoot = it.stateRoot,
            rootlessUser = it.user,
            envFilePrefix = "%t/${activePodmanPolicy.unitPrefix}",
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

data class LoopbackEndpoint(
    val service: String,
    val containerPort: String,
    val hostPort: Int,
    val protocol: String = "tcp",
    val consumers: Set<String> = setOf("rootful")
)
fun podmanNetworkName(domain: PodmanDomain, name: String): String =
    if (domain.name == "rootful") "${activePodmanPolicy.unitPrefix}_$name" else "${activePodmanPolicy.unitPrefix}_${domain.name}_$name"

fun qualifiedImage(image: String, updatePolicy: String): String {
    if (image.matches(Regex("sha256:[0-9a-f]{64}"))) {
        if (updatePolicy != "pinned") fail("local image IDs require pinned update policy")
        return image
    }
    // Installation must use the locked digest even when the module historically
    // requested registry updates. Never resolve a digest-only reference as latest.
    var ref = image
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

// Compose expands unescaped variables from the sealed deployment environment;
// escaped dollars belong to the container shell. Keep values out of public
// Quadlets/argv by passing only referenced inputs through the private env file.
val healthInput = Regex("(?<!\\$)\\$(?:\\{([A-Z_][A-Z0-9_]*)|([A-Z_][A-Z0-9_]*))")
fun podmanSecurityOptions(service: JsonNode): List<String> {
    val options = service.path("securityOpt")
    if (options.isMissingNode) return emptyList()
    if (!options.isArray) fail("securityOpt must be an array")
    val values = options.map { option ->
        if (!option.isTextual) fail("securityOpt entries must be strings")
        option.asText()
    }
    if (values.size != values.toSet().size) fail("duplicate securityOpt")
    if (values.any { it !in setOf("no-new-privileges", "no-new-privileges:true", "no-new-privileges=true") }) {
        fail("unsupported or weakening Podman securityOpt")
    }
    return if (values.isEmpty()) emptyList() else listOf("NoNewPrivileges=true")
}

fun podmanRestartPolicy(service: JsonNode): String {
    val policy = service.get("restart") ?: return "on-failure"
    if (!policy.isTextual) fail("restart must be a supported policy string")
    return when (policy.asText()) {
        "no" -> "no"
        "always", "unless-stopped" -> "always"
        "on-failure" -> "on-failure"
        else -> fail("unsupported Podman restart policy")
    }
}

data class PodmanHealth(val command: String?, val inputs: Map<String, String>)
fun podmanHealth(service: JsonNode): PodmanHealth {
    val health = service.path("health")
    if (health.isMissingNode || health.isNull || health.isEmpty || health.path("disable").asBoolean(false))
        return PodmanHealth(null, emptyMap())
    val test = health.path("test")
    if (!test.isArray || test.isEmpty || test.any { !it.isTextual }) fail("health.test must be a nonempty string array")
    val parts = test.map(JsonNode::asText)
    if (parts == listOf("NONE")) return PodmanHealth(null, emptyMap())
    if (parts.size < 2) fail("health.test requires a command")
    val inputs = linkedMapOf<String, String>()
    val arguments = when (parts.first()) {
        "CMD-SHELL" -> {
            if (parts.size != 2) fail("CMD-SHELL health.test requires exactly one shell fragment")
            val command = healthInput.replace(parts[1]) { match ->
                val key = match.groupValues[1].ifEmpty { match.groupValues[2] }
                val alias = "P0_HEALTH_INPUT_$key"
                if (service.path("environment").has(alias)) fail("reserved health input collision: $alias")
                inputs[alias] = "\${$key}"
                if (match.groupValues[1].isNotEmpty()) "\${$alias" else "$$alias"
            }
            listOf("/bin/sh", "-c", command)
        }
        "CMD" -> {
            // No shell may be silently introduced into exec-form probes.
            if (parts.drop(1).any { healthInput.containsMatchIn(it) })
                fail("exec-form health input interpolation requires a rendered argv contract")
            parts.drop(1)
        }
        else -> fail("unsupported health.test mode '${parts.first()}'")
    }
    return PodmanHealth(json.writer().without(SerializationFeature.INDENT_OUTPUT).writeValueAsString(arguments), inputs)
}

fun isolatedCaddyProbe(raw: String): String {
    val first = "wget --quiet --tries=1 --spider --timeout=5"
    val config = "http://127.0.0.1:2019/config/"
    val upstreams = "http://127.0.0.1:2019/reverse_proxy/upstreams"
    val validate = "caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile"
    if (raw.split(config).size != 2 || raw.split(upstreams).size != 2 ||
        raw.split(first).size != 3 || raw.indexOf(validate) <= raw.indexOf(upstreams) ||
        !raw.substringBefore(first).contains("test -s /ca/caddy-ca.crt"))
        fail("unsupported isolated Caddy health source; admin API must remain off")
    // The isolated Caddy has admin off. Its dispatcher separately verifies a
    // hostname/trust-checked TLS handshake before other managers can start.
    return raw.substringBefore(first) +
        "test -s /certs/pki/authorities/local/root.crt && pidof caddy >/dev/null && " +
        raw.substring(raw.indexOf(validate))
}

fun podmanDns(service: JsonNode, isolated: Boolean, serviceName: String = ""): List<String> {
    val value = service.path("dns")
    val configured = when {
        value.isMissingNode || value.isNull -> emptyList()
        value.isTextual -> listOf(value.asText())
        value.isArray -> value.map { if (!it.isTextual) fail("dns must contain resolver strings") else it.asText() }
        else -> fail("dns must be a resolver string or array")
    }
    if (!isolated) return configured
    // The isolated selector/network authority already binds virbr140 and this
    // gateway. Preserve canonical OIDC :443 through its private TLS relay, not
    // the host/public resolver or an original deployment. Never add fallback.
    val gateway = "192.168.140.1"
    // Translate only the selected mail producer's exact upstream defaults, just
    // as this profile translates its publishers/binds. Never retain them as a
    // fallback, change default-profile choices, or admit arbitrary overrides.
    if (serviceName == "mailserver" && configured == listOf("8.8.8.8", "8.8.4.4")) return listOf(gateway)
    if (configured.any { it != gateway }) fail("isolated DNS cannot escape its private ingress authority")
    return listOf(gateway)
}

fun podmanExtraHosts(service: JsonNode, isolated: Boolean): List<String> = service.path("extraHosts").map { entry ->
    val value = entry.asText()
    if (!isolated) value else {
        val host = value.substringBefore(':')
        val canonical = host == "datamancy.net" || host.endsWith(".datamancy.net")
        if (!canonical) value else {
            // This selected private profile's DNS/TLS authority is virbr140.
            // Rootless host-gateway becomes pasta's 169.254.1.2, NOT this
            // authority; /etc/hosts would override the correct private DNS.
            val target = value.substringAfter(':', "")
            if (target !in setOf("host-gateway", "192.168.140.1")) fail("isolated canonical host alias escapes private ingress")
            "$host:192.168.140.1"
        }
    }
}

fun renderEnvironmentTemplate(name: String, service: ObjectNode, output: Path) {
    val environment = service.path("environment").fieldsMap().toMap().toMutableMap()
    podmanHealth(service).inputs.forEach { (key, value) -> environment[key] = nodes.textNode(value) }
    if (environment.isEmpty()) return
    val lines = environment.toSortedMap().entries.joinToString("\n") { (key, value) ->
        val rendered = if (value.isNull) "\${$key}" else value.asText().replace("\n", "\\n")
        "$key=$rendered"
    }
    output.resolve("runtime-env/$name.env.template").apply { parent.createDirectories(); writeText(lines + "\n") }
}

fun rewriteCrossDomainConfigs(ir: ObjectNode, output: Path) {
    val configRoot = output.resolve("runtime/configs")
    if (!configRoot.isDirectory()) return
    val owners = mutableMapOf<String, MutableSet<String>>()
    ir.path("services").fieldsMap().forEach { (_, service) ->
        val domain = podmanDomainForService(service).name
        service.path("volumes").forEach { mount ->
            val source = if (mount.isTextual) mount.asText().substringBefore(':') else mount.path("source").asText()
            if (source.startsWith("./configs/")) {
                val relative = source.removePrefix("./configs/")
                if (relative.isNotBlank()) owners.getOrPut(relative) { linkedSetOf() }.add(domain)
            }
        }
    }
    configRoot.toFile().walkTopDown().filter(File::isFile).forEach { file ->
        val relative = configRoot.relativize(file.toPath())
        val domains = owners.entries
            .filter { (mount, _) -> relative.toString() == mount || (configRoot.resolve(mount).isDirectory() && relative.startsWith(mount)) }
            .flatMapTo(linkedSetOf()) { it.value }
        if (domains.isEmpty()) return@forEach
        val original = runCatching { file.readText() }.getOrNull() ?: return@forEach
        if ('\u0000' in original) return@forEach
        var content = original
        activePodmanPolicy.crossDomainEndpoints
            .filter { endpoint -> domains.any { it in endpoint.consumers } }
            .forEach { endpoint ->
                content = rewriteEndpointConfigText(content, endpoint.service, endpoint.containerPort, endpoint.hostPort)
            }
        if (content != original) file.writeText(content)
    }
}

fun loopbackEndpoints(ir: ObjectNode, output: Path): Map<String, List<LoopbackEndpoint>> {
    rewriteCrossDomainConfigs(ir, output)
    if (activePodmanPolicy.unitPrefix != "webservices") {
        val livekit = output.resolve("runtime/configs/livekit/livekit.yaml")
        if (!livekit.isRegularFile()) fail("isolated Livekit config missing")
        var config = livekit.readText()
        for ((protocol, oldPort) in listOf("tcp" to 7881, "udp" to 7882)) {
            val original = "  ${protocol}_port: $oldPort"
            val mapped = activePodmanPolicy.portMap[oldPort] ?: fail("missing isolated Livekit ICE port")
            if (config.split(original).size != 2) fail("unreviewed Livekit ICE config")
            config = config.replace(original, "  ${protocol}_port: $mapped")
        }
        livekit.writeText(config)
    }
    val endpoints = linkedMapOf<Triple<String, String, String>, LoopbackEndpoint>()
    activePodmanPolicy.crossDomainEndpoints.forEach { endpoint ->
        endpoints[Triple(endpoint.service, endpoint.containerPort.toString(), endpoint.protocol)] = LoopbackEndpoint(
            endpoint.service,
            endpoint.containerPort.toString(),
            endpoint.hostPort,
            endpoint.protocol,
            endpoint.consumers
        )
    }
    val caddyFile = output.resolve("runtime/configs/caddy/Caddyfile")
    if (caddyFile.isRegularFile()) {
        val knownServices = ir.path("services").fieldsMap().map { it.first }.toSet()
        val endpointPattern = Regex("\\b([a-z0-9][a-z0-9-]*):(\\d{2,5})\\b")
        var nextCaddyPort = 18080
        endpointPattern.findAll(caddyFile.readText()).forEach { match ->
            val service = match.groupValues[1]
            val port = match.groupValues[2]
            if (service in knownServices) {
                val key = Triple(service, port, "tcp")
                val existing = endpoints[key]
                if (existing != null) {
                    endpoints[key] = existing.copy(consumers = existing.consumers + "rootful")
                } else {
                    while (endpoints.values.any { it.hostPort == nextCaddyPort && it.protocol == "tcp" }) nextCaddyPort++
                    val originalPort = nextCaddyPort++
                    val mappedPort = if (activePodmanPolicy.unitPrefix == "webservices") originalPort else
                        activePodmanPolicy.portMap[originalPort] ?: fail("missing isolated Caddy upstream port $originalPort")
                    endpoints[key] = LoopbackEndpoint(service, port, mappedPort)
                }
            }
        }
        var rewritten = caddyFile.readText()
        if (activePodmanPolicy.unitPrefix != "webservices") {
            val vm = readTree(output.resolve("site/agent-vm.json"))
            val network = vm.path("networkConfig")
            val guestAddress = network.path("address").asText()
            val gateway = network.path("gateway").asText()
            if (!guestAddress.matches(Regex("192\\.168\\.140\\.[1-9][0-9]{0,2}/24")) ||
                guestAddress.substringBefore('/').split('.').last().toInt() !in 2..254 ||
                gateway != "192.168.140.1") {
                fail("isolated Caddy device API requires the reviewed private guest network")
            }
            val originalDeviceApi = "reverse_proxy 192.168.122.235:24838"
            if (rewritten.split(originalDeviceApi).size != 2) fail("unreviewed Caddy device API authority")
            rewritten = rewritten.replace(originalDeviceApi,
                "reverse_proxy ${guestAddress.substringBefore('/')}:24838")
            val oldLivekit = "reverse_proxy host.containers.internal:7880"
            if (rewritten.split(oldLivekit).size != 2) fail("unreviewed Caddy Livekit SFU authority")
            val mappedLivekit = activePodmanPolicy.portMap[7880] ?: fail("missing isolated Livekit API port")
            rewritten = rewritten.replace(oldLivekit, "reverse_proxy 127.0.0.1:$mappedLivekit")
            val key = Triple("livekit", "7880", "tcp")
            if (key in endpoints) fail("duplicate isolated Livekit API loopback endpoint")
            endpoints[key] = LoopbackEndpoint("livekit", "7880", mappedLivekit, "tcp", setOf("rootful"))
        }
        endpoints.values.filter { "rootful" in it.consumers }.forEach { endpoint ->
            rewritten = rewritten.replace(
                Regex("\\b${Regex.escape(endpoint.service)}:${Regex.escape(endpoint.containerPort)}\\b"),
                "127.0.0.1:${endpoint.hostPort}"
            )
        }
        if (activePodmanPolicy.unitPrefix != "webservices") {
            if ("http://{\$DOMAIN}" in rewritten) fail("unreviewed Caddy HTTP redirect source")
            rewritten += "\nhttp://{\$DOMAIN}, http://*.{\$DOMAIN} {\n\tredir https://{host}{uri} 308\n}\n"
        }
        caddyFile.writeText(rewritten)
    }
    val testDomain = activePodmanPolicy.domains.firstOrNull { it.name == "test-runners" }
    if (testDomain != null) {
        endpoints.entries.toList().forEach { (key, endpoint) ->
            val providerDomain = podmanDomainForService(ir.path("services").path(endpoint.service)).name
            if (providerDomain == "rootful" || providerDomain in testDomain.allowDependencies) {
                endpoints[key] = endpoint.copy(consumers = endpoint.consumers + testDomain.name)
            }
        }
    }
    if (endpoints.isEmpty()) return emptyMap()
    val rows = arr()
    endpoints.values.sortedWith(compareBy({ it.service }, { it.containerPort }, { it.protocol })).forEach { endpoint ->
        rows.add(obj().also { row ->
            row.put("service", endpoint.service)
            row.put("containerPort", endpoint.containerPort)
            row.put("hostPort", endpoint.hostPort)
            row.put("protocol", endpoint.protocol)
            row.set<ArrayNode>("consumers", arr().addAll(endpoint.consumers.sorted().map(nodes::textNode)))
            row.put("url", "http://127.0.0.1:${endpoint.hostPort}")
        })
    }
    writeJson(output.resolve("podman-loopback-endpoints.json"), obj().set<ArrayNode>("endpoints", rows))
    renderEndpointNftables(ir, endpoints.values.toList(), output)
    return endpoints.values.groupBy { it.service }
}

fun renderEndpointNftables(ir: ObjectNode, endpoints: List<LoopbackEndpoint>, output: Path) {
    val uidByDomain = activePodmanPolicy.domains.associate { domain ->
        domain.name to (domain.uid ?: fail("nftables endpoint policy requires a fixed uid for domain '${domain.name}'"))
    }
    val portsByUidProtocol = linkedMapOf<Pair<Int, String>, MutableSet<Int>>()
    endpoints.forEach { endpoint ->
        val provider = ir.path("services").path(endpoint.service)
        val providerDomain = podmanDomainForService(provider).name
        val allowedDomains = endpoint.consumers + providerDomain
        val uids = allowedDomains.map { if (it == "rootful") 0 else uidByDomain[it] ?: fail("unknown endpoint domain '$it'") } + 0
        uids.forEach { uid -> portsByUidProtocol.getOrPut(uid to endpoint.protocol) { linkedSetOf() }.add(endpoint.hostPort) }
    }
    val allByProtocol = endpoints.groupBy { it.protocol }.mapValues { (_, values) -> values.map { it.hostPort }.toSortedSet() }
    val lines = mutableListOf("table inet platform_zero {", "  chain output {", "    type filter hook output priority -10; policy accept;")
    portsByUidProtocol.toSortedMap(compareBy<Pair<Int, String>>({ it.first }, { it.second })).forEach { (key, ports) ->
        val (uid, protocol) = key
        lines += "    meta skuid $uid $protocol dport { ${ports.sorted().joinToString(", ")} } accept"
    }
    allByProtocol.toSortedMap().forEach { (protocol, ports) ->
        val values = ports.joinToString(", ")
        lines += "    ip daddr 127.0.0.0/8 $protocol dport { $values } reject"
        lines += "    ip6 daddr ::1 $protocol dport { $values } reject"
    }
    lines += listOf("  }", "}")
    output.resolve("ops/platform-zero.nft").apply { parent.createDirectories(); writeText(lines.joinToString("\n", postfix = "\n")) }
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

fun resourceLimit(node: JsonNode, kind: String): String? {
    if (node.isMissingNode || node.isNull) return null
    val raw = node.asText().trim()
    if (raw.isEmpty()) return null
    val defaultExpression = Regex("^\\$\\{[A-Z_][A-Z0-9_]*:-([^}]+)}$")
    val resolvedValue = defaultExpression.matchEntire(raw)?.groupValues?.get(1)?.trim() ?: raw
    // Compose/Podman accept lower-case magnitude suffixes; systemd MemoryMax
    // needs their canonical spelling. Keep the same concrete-size validation.
    val resolved = if (kind == "memory") resolvedValue.replace(Regex("[kmgtpe](?=[iIbB]*$)")) { it.value.uppercase() } else resolvedValue
    when (kind) {
        "memory" -> if (!resolved.matches(Regex("^[1-9][0-9]*(?:\\.[0-9]+)?[KMGTPE]?[iI]?[bB]?$"))) {
            fail("invalid resources.limits.memory '$raw'; use a concrete Podman size or ${'$'}{VAR:-default}")
        }
        "cpus" -> if (!resolved.matches(Regex("^(?:[1-9][0-9]*|0\\.[0-9]+|[1-9][0-9]*\\.[0-9]+)$")) || resolved.toDouble() <= 0.0) {
            fail("invalid resources.limits.cpus '$raw'; use a positive number or ${'$'}{VAR:-default}")
        }
        "pids" -> if (!resolved.matches(Regex("^[1-9][0-9]*$"))) {
            fail("invalid resources.limits.pids '$raw'; use a positive integer")
        }
        else -> fail("unsupported resource limit '$kind'")
    }
    return resolved
}

fun renderQuadletService(name: String, service: ObjectNode, ir: ObjectNode, output: Path, domain: PodmanDomain, loopbacks: Map<String, List<LoopbackEndpoint>>) {
    val unitPrefix = activePodmanPolicy.unitPrefix
    val health = podmanHealth(service)
    val notifyHealthy = ir.path("services").fieldsMap().any { (_, consumer) ->
        consumer.path("dependencies").path(name).asText() == "healthy"
    }
    if (notifyHealthy && (health.command == null || service.path("lifecycle").asText() != "daemon"))
        fail("healthy dependency '$name' requires an enabled daemon healthcheck")
    val isolatedVolumeInit = unitPrefix != "webservices" && name == "volume-init"
    if (isolatedVolumeInit && (domain.name != "rootful" || service.path("lifecycle").asText() != "oneshot"))
        fail("isolated volume-init requires rootful oneshot authority")
    val volumeReady = "${domain.stateRoot}/volume-ready-r1.txt"
    val quadlet = output.resolve("${domain.quadletDir}/$unitPrefix-$name.container")
    quadlet.parent.createDirectories()
    val dependencies = service.path("dependencies").fieldsMap()
        .filter { (dependency, _) ->
            podmanDomainForService(ir.path("services").path(dependency)).name == domain.name
        }
    val lines = mutableListOf<String>()
    lines += "[Unit]"
    lines += "Description=Webservices container: $name"
    if (isolatedVolumeInit) lines += "AssertFileNotEmpty=$volumeReady"
    dependencies.forEach { (dependency, _) ->
        lines += "Requires=$unitPrefix-$dependency.service"
        lines += "After=$unitPrefix-$dependency.service"
    }
    lines += "PartOf=$unitPrefix-${service.path("target").asText("apps")}.target"
    lines += ""
    lines += "[Container]"
    service.path("build").takeUnless { it.isMissingNode || service.has("frozenBuildImage") }
        ?.let { lines += "Image=$unitPrefix-$name.build" }
        ?: lines.add("Image=${qualifiedImage(service.path("image").asText(), service.path("updatePolicy").asText("pinned"))}")
    if (service.path("image").asText().matches(Regex("sha256:[0-9a-f]{64}"))) lines += "Pull=never"
    lines += "ContainerName=${if (unitPrefix == "webservices") name else "$unitPrefix-$name"}"
    if (service.path("lifecycle").asText() == "daemon" && service.path("updatePolicy").asText() == "registry" && !service.path("image").asText().contains('@')) lines += "AutoUpdate=registry"
    if ((service.path("environment").isObject && !service.path("environment").isEmpty) || health.inputs.isNotEmpty())
        lines += "EnvironmentFile=${domain.envFilePrefix}/$name.env"
    val hostNetwork = name == "caddy" || (service.path("hostNetwork").asBoolean(false) &&
        !(unitPrefix != "webservices" && name == "livekit"))
    if (hostNetwork) {
        lines += "Network=host"
    } else {
        // Namespace the engine object, not the module's intra-network DNS API.
        // Environment/dependency URLs still use the original service identity.
        if (unitPrefix != "webservices") lines += "NetworkAlias=$name"
        service.path("networks").let { networkNode ->
            if (networkNode.isArray) networkNode.forEach { lines += "Network=$unitPrefix-${it.asText()}.network" }
            else networkNode.fieldsMap().forEach { (network, config) ->
                lines += "Network=$unitPrefix-$network.network"
                config.path("aliases").forEach { lines += "NetworkAlias=${it.asText()}" }
            }
        }
        if (domain.name != "rootful" && activePodmanPolicy.crossDomainEndpoints.any { domain.name in it.consumers }) {
            lines += "Network=$unitPrefix-p0-egress.network"
        }
    }
    if (isolatedVolumeInit) {
        // Only the guarded host installer can write this root-private ready
        // marker after it has checked ACTUAL domain-owned bind paths/ACLs.
        // Never execute the source module's broad mkdir/chmod/chown shell.
        lines += "Volume=$volumeReady:/run/p0-venue-volume-ready.txt:ro"
    } else service.path("volumes").forEach { lines += "Volume=${quadletLiteral(volumeLine(it, ir.path("volumes"), domain))}" }
    val limits = service.path("resources").path("limits")
    val podmanArgs = mutableListOf("--image-volume=ignore")
    // Podman 5.4 Quadlet Notify= accepts booleans only. PodmanArgs follows its
    // default --sdnotify=conmon, so the last flag selects native health readiness.
    if (notifyHealthy) podmanArgs += "--sdnotify=healthy"
    resourceLimit(limits.path("memory"), "memory")?.let { podmanArgs += "--memory=$it" }
    resourceLimit(limits.path("cpus"), "cpus")?.let { podmanArgs += "--cpus=$it" }
    service.path("pidMode").textOrNull()?.let {
        if (it !in setOf("host", "private")) fail("unsupported PID namespace mode")
        if (activePodmanPolicy.standalone && it == "host" &&
            (name != "node-exporter" || service.path("user").asText() != "65534:65534" ||
             !service.path("readOnly").asBoolean(false) || "ALL" !in service.path("capDrop").map(JsonNode::asText)))
            fail("unreviewed standalone host PID namespace authority")
        // Podman 5.4 Quadlet has no [Container] Pid= directive. Preserve the
        // reviewed namespace through its native engine argument instead.
        podmanArgs += "--pid=$it"
    }
    lines += "PodmanArgs=${podmanArgs.joinToString(" ")}"
    service.path("ephemeralImageVolumes").forEach { lines += "Tmpfs=${it.asText()}" }
    service.path("userns").textOrNull()?.let { lines += "UserNS=$it" }
    service.path("groupAdd").forEach { lines += "GroupAdd=${it.asText()}" }
    service.path("devices").forEach { lines += "AddDevice=${it.asText()}" }
    resourceLimit(limits.path("pids"), "pids")?.let { lines += "PidsLimit=$it" }
    if (!hostNetwork) {
        service.path("ports").forEach { port ->
            val value = if (port.isTextual) port.asText() else {
                val protocol = port.path("protocol").asText("tcp").let { if (it == "tcp") "" else "/$it" }
                "${port.path("published").asText()}:${port.path("target").asText()}$protocol"
            }
            val portMatch = Regex("^((?:127\\.0\\.0\\.1:)?)([0-9]{1,5}):(.+)$").matchEntire(value)
                ?: fail("unsupported published port shape for '$name'")
            val oldPort = portMatch.groupValues[2].toInt()
            val hostPort = if (unitPrefix == "webservices") oldPort else
                activePodmanPolicy.portMap[oldPort] ?: fail("missing isolated published port $oldPort")
            // Synthetic mail ingress must not retain the selected public
            // 0.0.0.0 publishers. A later device-bound TLS relay is the only
            // permitted guest transport; host-side consumers keep loopback.
            val bindIp = when {
                unitPrefix != "webservices" && name == "mailserver" -> "127.0.0.1:"
                unitPrefix != "webservices" && name == "livekit" && oldPort in setOf(7881, 7882) -> "192.168.140.1:"
                else -> portMatch.groupValues[1]
            }
            val containerTarget = if (unitPrefix != "webservices" && name == "livekit" && oldPort in setOf(7881, 7882)) {
                "$hostPort${if (portMatch.groupValues[3].endsWith("/udp")) "/udp" else "/tcp"}"
            } else portMatch.groupValues[3]
            lines += "PublishPort=$bindIp$hostPort:$containerTarget"
        }
    }
    if (!hostNetwork) {
        loopbacks[name].orEmpty().forEach { endpoint ->
            val suffix = if (endpoint.protocol == "tcp") "" else "/${endpoint.protocol}"
            lines += "PublishPort=127.0.0.1:${endpoint.hostPort}:${endpoint.containerPort}$suffix"
        }
    }
    podmanExtraHosts(service, unitPrefix != "webservices").forEach { lines += "AddHost=$it" }
    podmanDns(service, unitPrefix != "webservices", name).forEach { lines += "DNS=$it" }
    service.path("tmpfs").forEach { lines += "Tmpfs=${it.asText()}" }
    service.path("capAdd").forEach { lines += "AddCapability=${it.asText()}" }
    service.path("capDrop").forEach { lines += "DropCapability=${it.asText()}" }
    lines += podmanSecurityOptions(service)
    if (service.path("readOnly").asBoolean(false)) lines += "ReadOnly=true"
    if (service.path("init").asBoolean(false)) lines += "RunInit=true"
    service.path("user").textOrNull()?.let { lines += "User=$it" }
    service.path("workingDir").textOrNull()?.let { lines += "WorkingDir=$it" }
    service.path("hostname").textOrNull()?.let { lines += "HostName=$it" }
    val entrypoint = service.path("entrypoint")
    val command = service.path("command")
    val execParts = mutableListOf<String>()
    if (isolatedVolumeInit) {
        lines += "Entrypoint=/bin/sh"
        execParts += "-ec"
        execParts += "grep -qx '${unitPrefix}-volume-ready-v1' /run/p0-venue-volume-ready.txt"
    } else if (!entrypoint.isMissingNode) {
        if (entrypoint.isArray && !entrypoint.isEmpty) {
            lines += "Entrypoint=${systemdQuote(entrypoint.first().asText())}"
            entrypoint.drop(1).forEach { execParts += it.asText() }
        } else lines += "Entrypoint=${systemdQuote(entrypoint.asText())}"
    }
    if (!isolatedVolumeInit && !command.isMissingNode) {
        if (command.isArray) command.forEach { execParts += it.asText() } else execParts += shellWords(command.asText())
    }
    if (name == "alloy" && unitPrefix != "webservices") {
        if (execParts != listOf("run", "/etc/alloy/alloy.hcl")) fail("unreviewed isolated Alloy command")
        execParts.add(1, "--server.http.listen-addr=127.0.0.1:12345")
    }
    if (execParts.isNotEmpty()) lines += "Exec=${execParts.joinToString(" ") { systemdQuote(it) }}"
    stopTimeoutSeconds(service.path("stopGracePeriod"))?.let { lines += "StopTimeout=$it" }
    health.command?.let { command ->
        // HealthCmd is a raw string, not a Quadlet argument list. JSON already
        // preserves argv/newlines; an outer systemdQuote would corrupt the JSON.
        val literal = command.replace("\$\$", "\$").replace("$", "\$\$").replace("%", "%%")
        lines += "HealthCmd=$literal"
        val config = service.path("health")
        mapOf("interval" to "HealthInterval", "timeout" to "HealthTimeout", "start_period" to "HealthStartPeriod").forEach { (key, option) ->
            config.get(key)?.let { value ->
                stopTimeoutSeconds(value) // Reject invalid durations before producing unit syntax.
                lines += "$option=${value.asText()}"
            }
        }
        config.get("retries")?.let { value ->
            if (!value.isIntegralNumber || value.asLong() < 1) fail("health.retries must be a positive integer")
            lines += "HealthRetries=${value.asLong()}"
        }
    }
    lines += "LogDriver=journald"
    lines += ""
    lines += "[Service]"
    if (domain.name == "rootful" && (unitPrefix != "webservices" || domain.graphRoot != null)) {
        lines += "Environment=CONTAINERS_STORAGE_CONF=${rootfulEngineConfigRoot()}/containers-storage.conf"
        lines += "Environment=CONTAINERS_CONF=${rootfulEngineConfigRoot()}/containers.conf"
        lines += nativeRootfulEngineServiceLines(domain)
        // Podman5.4 transient health timers forward PATH only and would open the
        // original/default root store. The scoped native adapter owns this cadence.
        lines += "Environment=DISABLE_HC_SYSTEMD=true"
    }
    if (service.path("lifecycle").asText() == "oneshot") {
        lines += "Type=oneshot"
        lines += "RemainAfterExit=yes"
        lines += "Restart=no"
    } else {
        lines += "Restart=${podmanRestartPolicy(service)}"
        lines += "RestartSec=5s"
        lines += "TimeoutStartSec=900"
        lines += "TimeoutStopSec=120"
    }
    lines += ""
    lines += "[Install]"
    if (service.path("lifecycle").asText() != "on-demand") lines += "WantedBy=$unitPrefix-${service.path("target").asText("apps")}.target"
    quadlet.writeText(lines.joinToString("\n", postfix = "\n"))
    renderEnvironmentTemplate(name, service, output)

    service.path("build").takeUnless(JsonNode::isMissingNode)?.let { build ->
        val buildLines = mutableListOf<String>()
        if (service.has("frozenBuildImage")) {
            // Retain reviewed recipe/unit identity, but never run a mutable
            // network build as part of an immutable installed release.
            buildLines += listOf("[Unit]", "RefuseManualStart=yes", "")
        }
        buildLines += "[Build]"
        buildLines += "ImageTag=localhost/webservices/$name:bundle"
        build.path("context").textOrNull()?.let {
            val relativeContext = it.removePrefix("./").let { context -> if (context == "." || context == "build") "" else context }
            val workingDirectory = "${domain.releaseRoot}/build" + if (relativeContext.isBlank()) "" else "/$relativeContext"
            buildLines += "SetWorkingDirectory=${systemdQuote(workingDirectory)}"
        }
        build.path("containerfile").textOrNull()?.let { buildLines += "File=${systemdQuote(it)}" }
        // The isolated venue must preload each reviewed build base in its
        // exclusive graph. Never silently advance a mutable FROM tag while
        // executing a generated build unit. Legacy units are unchanged.
        if (unitPrefix != "webservices") {
            buildLines += "Pull=never"
            // Four selected Containerfiles need no build-time egress.
            // Other builds may discover candidate outputs only; their
            // network-fetched dependencies still require reviewed output pins.
            if (name in setOf("keycloak", "onboarding", "mastodon-rss-publisher", "firefly-native-api"))
                buildLines += "Network=none"
        }
        if (unitPrefix != "webservices" || activePodmanPolicy.standalone) {
            buildLines += "[Service]"
            // Native generated build oneshots otherwise inherit systemd's
            // short default timeout; the guarded build worker enforces the
            // same 30-minute ceiling and physical reserve independently.
            buildLines += "TimeoutStartSec=1800"
            if (activePodmanPolicy.standalone) {
                buildLines += listOf("MemoryMax=8G", "CPUQuota=200%", "TasksMax=512")
            }
            // Buildah's large layer-copy scratch must not silently consume
            // host /var/tmp. Reuse only the selected, UID-private SSD graph;
            // failed scratch remains subject to exact cleanup, never prune.
            val buildScratch = domain.graphRoot ?: activePodmanPolicy.rootfulGraphRoot
                ?: if (activePodmanPolicy.standalone) "${domain.releaseRoot}/build" else fail("venue build lacks a selected scratch graph")
            buildLines += "Environment=TMPDIR=$buildScratch"
            if (domain.name == "rootful" && (!activePodmanPolicy.standalone || domain.graphRoot != null)) {
                buildLines += "Environment=CONTAINERS_STORAGE_CONF=${rootfulEngineConfigRoot()}/containers-storage.conf"
                buildLines += "Environment=CONTAINERS_CONF=${rootfulEngineConfigRoot()}/containers.conf"
                buildLines += nativeRootfulEngineServiceLines(domain).filterNot { it.startsWith("Environment=TMPDIR=") }
            }
        }
        output.resolve("${domain.quadletDir}/$unitPrefix-$name.build").writeText(buildLines.joinToString("\n", postfix = "\n"))
    }
}

fun renderPodman(ir: ObjectNode, output: Path) {
    val unitPrefix = activePodmanPolicy.unitPrefix
    val loopbacks = loopbackEndpoints(ir, output)
    (listOf(rootfulDomain) + rootlessDomains).forEach { domain ->
        // Cumulative module rings retain idle actors and their closed targets.
        // Empty domains have no service/network writer to create this parent.
        output.resolve(domain.quadletDir).createDirectories()
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
            if (domain.name == "rootful" && (unitPrefix != "webservices" || domain.graphRoot != null)) {
                lines += "[Service]"
                lines += "Environment=CONTAINERS_STORAGE_CONF=${rootfulEngineConfigRoot()}/containers-storage.conf"
                lines += "Environment=CONTAINERS_CONF=${rootfulEngineConfigRoot()}/containers.conf"
                lines += nativeRootfulEngineServiceLines(domain)
            }
            output.resolve("${domain.quadletDir}/$unitPrefix-$name.network").apply { parent.createDirectories(); writeText(lines.joinToString("\n", postfix = "\n")) }
        }
        // Idle actors retain their target set, never an unreferenced bridge.
        // Match container emission exactly; selection must continue refusing
        // extra network authority rather than accepting unused source files.
        val hasContainers = ir.path("services").fieldsMap().any { (_, service) ->
            podmanDomainForService(service).name == domain.name && quadletEmitted(service)
        }
        if (hasContainers && domain.name != "rootful" && activePodmanPolicy.crossDomainEndpoints.any { domain.name in it.consumers }) {
            output.resolve("${domain.quadletDir}/$unitPrefix-p0-egress.network").apply {
                parent.createDirectories()
                writeText("[Network]\nNetworkName=${podmanNetworkName(domain, "p0-egress")}\nDriver=bridge\n")
            }
        }
        ir.path("services").fieldsMap()
            .filter { (_, service) ->
                podmanDomainForService(service).name == domain.name &&
                    quadletEmitted(service)
            }
            .forEach { (name, service) -> renderQuadletService(name, service as ObjectNode, ir, output, domain, loopbacks) }
        listOf("core", "apps", "observability").forEach { target ->
            val targetServices = ir.path("services").fieldsMap()
                .filter { (_, service) ->
                    podmanDomainForService(service).name == domain.name &&
                        service.path("target").asText("apps") == target &&
                        service.path("lifecycle").asText() != "on-demand"
                }
                .map { (name, _) -> "$unitPrefix-$name.service" }
                .sorted()
            val wants = if (targetServices.isEmpty()) "" else "Wants=${targetServices.joinToString(" ")}\n"
            output.resolve("${domain.quadletDir}/$unitPrefix-$target.target").writeText("[Unit]\nDescription=Webservices ${target.replaceFirstChar(Char::uppercase)} (${domain.name})\nPartOf=$unitPrefix.target\n${wants}\n[Install]\nWantedBy=$unitPrefix.target\n")
        }
        output.resolve("${domain.quadletDir}/$unitPrefix.target").writeText("[Unit]\nDescription=Platform Zero webservices stack (${domain.name})\nWants=$unitPrefix-core.target $unitPrefix-apps.target $unitPrefix-observability.target\n\n[Install]\nWantedBy=${domain.targetInstall}\n")
    }
    val generatorRoot = System.getenv("STACK_GENERATOR_ROOT")?.let(Path::of)
        ?: fail("STACK_GENERATOR_ROOT is not set")
    // Runtime imports may create root-private ignored __pycache__ entries.
    // Only reviewed tracked operations are release inputs, never interpreter
    // caches or other ignored/private files; do not chmod/read those caches.
    val ops = output.resolve("ops").createDirectories()
    val opsPrefix = "runtime-generator/podman-ops/"
    val trackedOps = commandOutput(listOf("git", "ls-files", "-z", "--", opsPrefix), generatorRoot)
        .split('\u0000').filter { it.isNotBlank() }
    if (trackedOps.isEmpty()) fail("missing tracked native operations")
    trackedOps.forEach { relative ->
        val name = relative.removePrefix(opsPrefix)
        val source = generatorRoot.resolve(relative)
        if (!relative.startsWith(opsPrefix) || name.contains('/') || name in setOf(".", "..") ||
            !Files.isRegularFile(source, LinkOption.NOFOLLOW_LINKS)) fail("unrecognized tracked native operation")
        Files.copy(source, ops.resolve(name), StandardCopyOption.COPY_ATTRIBUTES)
    }
    generatorRoot.resolve("ops/host-admin/provision-domain-accounts.sh")
        .copyTo(output.resolve("ops/provision-domain-accounts.sh"), overwrite = true)
    generatorRoot.resolve("ops/host-admin/migrate-domain-authorities.py")
        .copyTo(output.resolve("ops/migrate-domain-authorities.py"), overwrite = true)
    generatorRoot.resolve("ops/host-admin/retire-legacy-webservices-account.sh")
        .copyTo(output.resolve("ops/retire-legacy-webservices-account.sh"), overwrite = true)
    generatorRoot.resolve("ops/maintenance/materialize-workspaces.py")
        .copyTo(output.resolve("ops/materialize-workspaces.py"), overwrite = true)
    generatorRoot.resolve("ops/maintenance/start-worklane-containers.py")
        .copyTo(output.resolve("ops/start-worklane-containers.py"), overwrite = true)
    generatorRoot.resolve("ops/maintenance/platform-zero-worklanes.service")
        .copyTo(output.resolve("ops/platform-zero-worklanes.service"), overwrite = true)
    generatorRoot.resolve("ops/maintenance/reap-idle-worklanes.py")
        .copyTo(output.resolve("ops/reap-idle-worklanes.py"), overwrite = true)
    generatorRoot.resolve("ops/maintenance/platform-zero-worklane-idle-reaper.service")
        .copyTo(output.resolve("ops/platform-zero-worklane-idle-reaper.service"), overwrite = true)
    generatorRoot.resolve("ops/maintenance/platform-zero-worklane-idle-reaper.timer")
        .copyTo(output.resolve("ops/platform-zero-worklane-idle-reaper.timer"), overwrite = true)
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
        val persistentServices = ir.path("services").fieldsMap()
            .filter { (_, service) ->
                service.path("rootlessDomain").asText() == policy.name &&
                    service.path("lifecycle").asText("daemon") == "daemon"
            }
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
            row.put("maintenanceLane", policy.maintenanceLane)
            row.set<ArrayNode>("hostCapabilities", arr().addAll(policy.hostCapabilities.sorted().map(nodes::textNode)))
            row.set<ArrayNode>("modules", arr().addAll(policy.modules.sorted().map(nodes::textNode)))
            row.set<ArrayNode>("services", arr().addAll(services.map(nodes::textNode)))
            row.set<ArrayNode>("persistentServices", arr().addAll(persistentServices.map(nodes::textNode)))
            row.set<ArrayNode>("allowDependencies", arr().addAll(policy.allowDependencies.sorted().map(nodes::textNode)))
        })
    }
    val domainMetadata = obj().also {
        it.put("schemaVersion", 1)
        it.set<ArrayNode>("domains", domainRows)
    }
    if (activePodmanPolicy.unitPrefix != "webservices") {
        val venueMetadata = obj().put("schemaVersion", 1)
            .put("unitPrefix", activePodmanPolicy.unitPrefix)
            .put("rootfulStateRoot", activePodmanPolicy.rootfulStateRoot)
            .put("rootfulRuntimeRoot", "/run/${activePodmanPolicy.unitPrefix}")
            .put("rootfulGraphRoot", activePodmanPolicy.rootfulGraphRoot)
            .put("rootfulRunRoot", activePodmanPolicy.rootfulRunRoot)
            .put("rootfulVolumeRoot", activePodmanPolicy.venueVolumeRoot)
            .put("pgSsdRoot", activePodmanPolicy.venuePgSsdRoot)
            .put("vectorDbsRoot", activePodmanPolicy.venueVectorDbsRoot)
            .put("controlSocketRoot", activePodmanPolicy.venueControlSocketRoot)
            .put("logRoot", activePodmanPolicy.venueLogRoot)
        venueMetadata.set<ObjectNode>("portMap", obj().also { mapping ->
            activePodmanPolicy.portMap.toSortedMap().forEach { (original, proposed) -> mapping.put(original.toString(), proposed) }
        })
        domainMetadata.set<ObjectNode>("venue", venueMetadata)
    }
    if (standaloneHost(readTree(manifestPath))) {
        domainMetadata.put("deploymentMode", "standalone")
        domainMetadata.put("installerStateRoot", activePodmanPolicy.rootfulStateRoot)
        domainMetadata.put("caddyLogRoot", standaloneCaddyLogRoot())
        val manifest = readTree(manifestPath)
        domainMetadata.set<JsonNode>("storageScope", manifest.path("storageScope").deepCopy<JsonNode>())
        if (activePodmanPolicy.rootfulGraphRoot != null) {
            val state = activePodmanPolicy.rootfulStateRoot + "/rootful-store"
            domainMetadata.set<ObjectNode>("rootfulStore", obj().put("schemaVersion", 1)
                .put("kind", "standalone-owned-rootful-store")
                .put("scopeRoot", manifest.path("storageScope").path("root").asText())
                .put("scopeMarkerSha256", standaloneStorageMarkerSha(manifest))
                .put("stateRoot", state).put("dataRoot", "$state/graph")
                .put("graphRoot", activePodmanPolicy.rootfulGraphRoot).put("runRoot", activePodmanPolicy.rootfulRunRoot)
                .put("networkRoot", "$state/networks"))
        }
    }
    writeJson(output.resolve("podman-domains.json"), domainMetadata)

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

    // Host application installation must not prepare, dispatch or own lane workspaces.
    if (standaloneHost(readTree(manifestPath))) return
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
    workspaces.add(obj().put("name", "control").put("role", "control").put("startAtBoot", false).set<ArrayNode>("repositories", arr().also { rows ->
        baseline.forEach { rows.add(it.deepCopy().also { row -> row.put("writable", true) }) }
    }))
    workspaces.add(obj().put("name", "host").put("role", "host").put("startAtBoot", false).set<ArrayNode>("repositories", reposFor(activePodmanPolicy.rootfulModules)))
    activePodmanPolicy.domains.groupBy { it.maintenanceLane }.toSortedMap().forEach { (lane, domains) ->
        workspaces.add(obj().also { row ->
            row.put("name", lane)
            row.put("role", "domain")
            row.put("startAtBoot", false)
            row.set<ArrayNode>("authorities", arr().also { authorities ->
                domains.sortedBy { it.name }.forEach { domain ->
                    authorities.add(obj().put("name", domain.name).put("serviceAccount", domain.user))
                }
            })
            row.set<ArrayNode>("services", arr().addAll(domains.flatMap { domain ->
                domainRows.first { it.path("name").asText() == domain.name }.path("services").map(JsonNode::asText)
            }.distinct().sorted().map(nodes::textNode)))
            row.set<ArrayNode>("repositories", reposFor(domains.flatMap { it.modules }.toSet()))
        })
    }
    writeJson(output.resolve("maintenance-workspaces.json"), obj()
        .put("schemaVersion", 1)
        .put("owner", "stack_lab")
        .put("root", activePodmanPolicy.maintenanceRoot)
        .set<ArrayNode>("workspaces", workspaces))

    val stackConfig = readTree(manifestPath).path("stackConfig").asText()
    val software = readTree(manifestPath.parent.resolve(stackConfig).normalize()).path("podman").path("software_workspaces")
    if (software.isMissingNode) return
    if (!software.isObject) fail("podman.software_workspaces must be an object")
    val softwareOwner = software.path("owner").asText().ifBlank { fail("podman.software_workspaces.owner is required") }
    if (!softwareOwner.matches(Regex("[a-z_][a-z0-9_-]*"))) fail("invalid software workspace owner '$softwareOwner'")
    val softwareRoot = Path(software.path("root").asText().ifBlank { fail("podman.software_workspaces.root is required") }).normalize()
    if (!softwareRoot.isAbsolute || softwareRoot == Path("/")) fail("software workspace root must be an absolute non-root path")
    val defaultProfile = software.path("profile").asText("software-gpu")
    val devices = software.path("devices")
    if (!devices.isArray || devices.isEmpty || devices.any { !it.isTextual || it.asText().isBlank() }) {
        fail("podman.software_workspaces.devices must be a non-empty string array")
    }
    val lanes = software.path("lanes")
    if (!lanes.isArray || lanes.isEmpty) fail("podman.software_workspaces.lanes must be a non-empty array")
    val laneNames = mutableSetOf<String>()
    val softwareRows = arr()
    lanes.forEachIndexed { index, lane ->
        val label = "podman.software_workspaces.lanes[$index]"
        val name = lane.path("name").asText()
        if (!name.matches(Regex("[a-z0-9][a-z0-9_-]*")) || !laneNames.add(name)) fail("$label has an invalid or duplicate name")
        val projectPath = Path(lane.path("project_path").asText(softwareRoot.resolve(name).toString())).normalize()
        if (!projectPath.isAbsolute || (projectPath != softwareRoot && !projectPath.startsWith(softwareRoot))) fail("$label project_path escapes the software root")
        fun commandList(field: String): ArrayNode {
            val value = lane.path(field)
            if (value.isMissingNode) return arr()
            if (!value.isArray || value.any { !it.isTextual || it.asText().isBlank() }) fail("$label.$field must be a string array")
            return value.deepCopy<ArrayNode>()
        }
        val softwareRow = obj()
            .put("name", name)
            .put("role", "software")
            .put("projectPath", projectPath.toString())
            .put("profile", lane.path("profile").asText(defaultProfile))
            .put("startAtBoot", false)
        softwareRow.set<ArrayNode>("devices", devices.deepCopy<ArrayNode>())
        softwareRow.set<ArrayNode>("bootstrap", commandList("bootstrap"))
        softwareRow.set<ArrayNode>("smokeTest", commandList("smoke_test"))
        softwareRows.add(softwareRow)
    }
    writeJson(output.resolve("software-workspaces.json"), obj()
        .put("schemaVersion", 1)
        .put("owner", softwareOwner)
        .put("root", softwareRoot.toString())
        .set<ArrayNode>("workspaces", softwareRows))
}

fun replaceDirectory(staging: Path, output: Path) {
    if (output.exists()) output.toFile().deleteRecursively()
    try {
        Files.move(staging, output, StandardCopyOption.ATOMIC_MOVE)
    } catch (_: Exception) {
        Files.move(staging, output)
    }
}

fun normalizeArtifactPermissions(output: Path) {
    // Build output is secret-free except the explicitly declared encrypted store.
    // Do not inherit a root/operator umask into COPY inputs for non-root images.
    val store = readTree(output.resolve("site/manifest.json")).path("secretStore").asText()
    val encryptedStore = output.resolve("site").resolve(store).normalize()
    val readable = setOf(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE,
        PosixFilePermission.GROUP_READ, PosixFilePermission.OTHERS_READ)
    val executable = setOf(PosixFilePermission.OWNER_EXECUTE, PosixFilePermission.GROUP_EXECUTE,
        PosixFilePermission.OTHERS_EXECUTE)
    output.walk(PathWalkOption.INCLUDE_DIRECTORIES).forEach { path ->
        if (Files.isSymbolicLink(path)) fail("artifact contains symlink: ${output.relativize(path)}")
        val mode = when {
            path == encryptedStore -> setOf(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE)
            path.isDirectory() -> readable + executable
            Files.getPosixFilePermissions(path).any { it in executable } -> readable + executable
            else -> readable
        }
        Files.setPosixFilePermissions(path, mode)
    }
}

fun dropTransientPythonBytecode(staging: Path) {
    // Source checkouts may contain interpreter-generated caches, including
    // tracked historical .pyc files. They are never selected runtime source:
    // keep the original checkouts untouched, and exclude only bytecode from
    // this newly staged output before sealing bundle identity/provenance.
    val paths = Files.walk(staging).use { it.toList() }
        .sortedByDescending { it.nameCount }
    for (path in paths) {
        if (Files.isSymbolicLink(path)) fail("linked generated artifact cannot be normalized")
        if (Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)
                && (path.fileName.toString().endsWith(".pyc") || path.fileName.toString().endsWith(".pyo"))) {
            Files.delete(path)
        } else if (path != staging && Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS)
                && path.fileName.toString() == "__pycache__") {
            Files.list(path).use { children ->
                if (children.findAny().isPresent) fail("unreviewed Python cache directory content")
            }
            Files.delete(path)
        }
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
        applyResourceDefaults(ir, activePodmanPolicy)
        applyVenueBindPolicy(ir, activePodmanPolicy)
        applyCrossDomainEndpointPolicy(ir, activePodmanPolicy)
        applyStandaloneHostProfile(ir, readTree(manifest))
        freezeLocalBuildImages(ir, manifest)
        writeJson(staging.resolve("stack.ir.json"), ir)
        materializeSiteManifest(manifest, staging)
        materializeModules(modules, staging)
        materializeStandaloneHostInputs(readTree(manifest), staging)
        materializeGradleBuildInputs(staging)
        // Optional cached inputs must never overwrite artifacts compiled from selected source.
        materializeGeneratedBuildArtifacts(modules, staging)
        buildLocalArtifacts(staging)
        materializeRuntimeRendererInputs(staging)
        materializeComponentLock(manifest, staging, ir)
        writeJson(staging.resolve("source-provenance.json"), sourceProvenance(manifest, modules))
        renderRuntimeModel(ir, staging)
        if (backend == "podman") renderPodman(ir, staging)
        writeDomainMetadata(ir, modules, manifest, staging)
        dropTransientPythonBytecode(staging)
        val metadata = obj()
        metadata.put("schemaVersion", 1)
        metadata.put("backend", backend)
        if (standaloneHost(readTree(manifest))) metadata.put("deploymentMode", "standalone")
        metadata.put("irSha256", sha256(staging.resolve("stack.ir.json")))
        metadata.put("sourceProvenanceSha256", sha256(staging.resolve("source-provenance.json")))
        if (backend == "podman") {
            // Pin every emitted transitive native helper before the receipt
            // pins bundle.json. Never mint helper pins from an installed tree.
            val liveOps = obj()
            Files.list(staging.resolve("ops")).use { files ->
                files.sorted().forEach { source ->
                    val name = source.fileName.toString()
                    if (!Regex("[A-Za-z0-9][A-Za-z0-9_.-]*").matches(name) ||
                        !Files.isRegularFile(source, LinkOption.NOFOLLOW_LINKS)) {
                        fail("unrecognized native operations artifact")
                    }
                    liveOps.put("ops/$name", sha256(source))
                }
            }
            if (liveOps.size() == 0) fail("missing native operations pins")
            metadata.set<ObjectNode>("liveOps", liveOps)
        }
        metadata.set<ArrayNode>("deferredCapabilities", ir.path("deferredCapabilities").deepCopy())
        writeJson(staging.resolve("bundle.json"), metadata)
        normalizeArtifactPermissions(staging)
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

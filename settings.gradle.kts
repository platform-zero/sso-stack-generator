rootProject.name = "webservices"

include(":runtime-generator")
project(":runtime-generator").projectDir = file("runtime-generator")

val includedProjectNames = mutableSetOf<String>()

fun includeProjectIfPresent(projectName: String, relativePath: String) {
    val dir = file(relativePath)
    if (File(dir, "build.gradle.kts").isFile && includedProjectNames.add(projectName)) {
        include(":$projectName")
        project(":$projectName").projectDir = dir
    }
}

includeProjectIfPresent("pipeline-common", "stack.kotlin/pipeline-common")
includeProjectIfPresent("gpu-bootstrap-arbiter", "stack.kotlin/gpu-bootstrap-arbiter")
includeProjectIfPresent("gpu-workload-monitor", "stack.kotlin/gpu-workload-monitor")
includeProjectIfPresent("inference-gateway", "stack.kotlin/inference-gateway")
includeProjectIfPresent("inference-controller", "stack.kotlin/inference-controller")
includeProjectIfPresent("test-manager", "stack.kotlin/test-manager")
includeProjectIfPresent("test-runner", "stack.kotlin/test-runner")
includeProjectIfPresent("keycloak-onboarding-listener", "stack.kotlin/keycloak-onboarding-listener")
includeProjectIfPresent("progression", "stack.kotlin/progression")
includeProjectIfPresent("portal", "stack.kotlin/portal")

file("stack.kotlin")
    .takeIf { it.isDirectory }
    ?.listFiles()
    ?.filter { File(it, "build.gradle.kts").isFile }
    ?.sortedBy { it.name }
    ?.forEach { moduleDir ->
        includeProjectIfPresent(moduleDir.name, "stack.kotlin/${moduleDir.name}")
    }

file("out/external-modules/materialized/stack.kotlin")
    .takeIf { it.isDirectory }
    ?.listFiles()
    ?.filter { File(it, "build.gradle.kts").isFile }
    ?.sortedBy { it.name }
    ?.forEach { moduleDir ->
        includeProjectIfPresent(moduleDir.name, "out/external-modules/materialized/stack.kotlin/${moduleDir.name}")
    }

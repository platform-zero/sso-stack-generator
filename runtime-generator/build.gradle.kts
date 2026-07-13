plugins {
    base
}

val generatorRuntime by configurations.creating

dependencies {
    generatorRuntime("org.jetbrains.kotlin:kotlin-main-kts:2.0.21")
    generatorRuntime("org.jetbrains.kotlin:kotlin-compiler-embeddable:2.0.21")
    generatorRuntime("com.fasterxml.jackson.core:jackson-databind:2.17.1")
    generatorRuntime("com.fasterxml.jackson.dataformat:jackson-dataformat-yaml:2.17.1")
}

val classpathFile = layout.buildDirectory.file("generator-classpath.txt")

tasks.register("prepareGenerator") {
    inputs.files(generatorRuntime)
    outputs.file(classpathFile)
    doLast {
        classpathFile.get().asFile.apply {
            parentFile.mkdirs()
            writeText(generatorRuntime.asPath + System.lineSeparator())
        }
    }
}

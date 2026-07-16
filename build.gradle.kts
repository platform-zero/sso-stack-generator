import org.gradle.language.base.plugins.LifecycleBasePlugin

plugins {
    alias(libs.plugins.kover)
    alias(libs.plugins.kotlin.jvm) apply false
    alias(libs.plugins.kotlin.serialization) apply false
    alias(libs.plugins.shadow) apply false
}

allprojects {
    repositories {
        mavenCentral()
    }
}

dependencies {
    subprojects.forEach { project ->
        kover(project)
    }
}

subprojects {
    apply(plugin = "org.jetbrains.kotlin.jvm")
    apply(plugin = "org.jetbrains.kotlin.plugin.serialization")
    apply(plugin = "org.jetbrains.kotlinx.kover")
    apply(plugin = "com.github.johnrengelman.shadow")

    group = "org.webservices"
    version = "1.0-SNAPSHOT"

    extensions.configure<org.jetbrains.kotlin.gradle.dsl.KotlinJvmProjectExtension> {
        jvmToolchain(21)
    }

    tasks.withType<org.jetbrains.kotlin.gradle.tasks.KotlinCompile> {
        compilerOptions {
            allWarningsAsErrors.set(true)
        }
    }

    tasks.withType<Test> {
        useJUnitPlatform()

        // Development checkouts can materialize independently owned Kotlin
        // projects under out/. Their source-contract tests still need the
        // composed materialized tree and the sibling module workspace rather
        // than this generator checkout as their implicit source roots.
        val materializedRoot = rootProject.file("out/external-modules/materialized")
        if (project.projectDir.toPath().startsWith(materializedRoot.toPath())) {
            if (System.getenv("WEBSERVICES_GENERATOR_ROOT").isNullOrBlank()) {
                environment("WEBSERVICES_GENERATOR_ROOT", materializedRoot.absolutePath)
            }
            if (System.getenv("WEBSERVICES_MODULES_ROOT").isNullOrBlank()) {
                environment("WEBSERVICES_MODULES_ROOT", rootProject.file("../modules").absolutePath)
            }
        }
    }
}

tasks.register("test") {
    dependsOn(subprojects.map { it.tasks.named("test") })
}

tasks.register("coverageAll") {
    group = LifecycleBasePlugin.VERIFICATION_GROUP
    description = "Runs all Gradle JVM tests and generates merged Kover HTML and XML reports."
    dependsOn("koverHtmlReport", "koverXmlReport")
}

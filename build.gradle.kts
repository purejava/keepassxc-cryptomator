plugins {
    id("com.gradleup.shadow") version "8.3.6"
    id("com.github.breadmoirai.github-release") version "2.5.2"
    id("com.palantir.git-version") version "3.2.0"
    id("java")
    id("java-library")
    id("signing")
}

repositories {
    mavenCentral()
}

dependencies {
    api(libs.org.cryptomator.integrations.api)
    api(libs.org.slf4j.slf4j.api)
    api(libs.org.purejava.keepassxc.proxy.access)
    testImplementation(libs.org.slf4j.slf4j.simple)
    testImplementation(libs.org.junit.jupiter.junit.jupiter.api)
    testImplementation(libs.org.junit.jupiter.junit.jupiter.engine)
    testImplementation(libs.org.junit.jupiter.junit.jupiter)
    testRuntimeOnly(libs.org.junit.platform.junit.platform.launcher)
}

group = "org.purejava"
val gitVersion: groovy.lang.Closure<String> by extra
version = gitVersion() // version set by the plugin, based on the Git tag

val releaseGradlePluginToken: String = System.getenv("RELEASE_GRADLE_PLUGIN_TOKEN") ?: ""

java {
    sourceCompatibility = JavaVersion.VERSION_17
    withSourcesJar()
    withJavadocJar()
}

tasks.test {
    useJUnitPlatform()
    filter {
        includeTestsMatching("KeePassXCAccessTest")
    }
}

/*
publishing {
    publications {
        create<MavenPublication>("mavenJava") {
            from(components["java"])
            pom {
                name.set("keepassxc-cryptomator")
                description.set("Plug-in for Cryptomator to store vault passwords in KeePassXC")
                url.set("https://github.com/purejava/keepassxc-cryptomator")
                licenses {
                    license {
                        name.set("MIT License")
                        url.set("https://opensource.org/licenses/MIT")
                    }
                }
                developers {
                    developer {
                        id.set("purejava")
                        name.set("Ralph Plawetzki")
                        email.set("ralph@purejava.org")
                    }
                }
                scm {
                    connection.set("scm:git:git://github.com/purejava/keepassxc-cryptomator.git")
                    developerConnection.set("scm:git:ssh://github.com/purejava/keepassxc-cryptomator.git")
                    url.set("https://github.com/purejava/keepassxc-cryptomator/tree/main")
                }
                issueManagement {
                    system.set("GitHub Issues")
                    url.set("https://github.com/purejava/keepassxc-cryptomator/issues")
                }
            }
        }
    }
}
*/

tasks.named<com.github.jengelman.gradle.plugins.shadow.tasks.ShadowJar>("shadowJar") {
    archiveClassifier.set("")
}

artifacts {
    add("archives", tasks.named("shadowJar"))
}

signing {
    useGpgCmd()
    // Sign both the sources JAR and the shadow JAR
    sign(configurations.getByName("archives"))
}

tasks.withType<JavaCompile> {
    options.encoding = "UTF-8"
}

tasks.withType<Javadoc> {
    (options as StandardJavadocDocletOptions).encoding = "UTF-8"
    if (JavaVersion.current().isJava9Compatible) {
        (options as StandardJavadocDocletOptions).addBooleanOption("html5", true)
    }
}

githubRelease {
    token(releaseGradlePluginToken)
    tagName = project.version.toString()
    releaseName = project.version.toString()
    targetCommitish = "main"
    draft = true
    body = """
        [![Downloads](https://img.shields.io/github/downloads/purejava/keepassxc-cryptomator/latest/keepassxc-cryptomator-${project.version}.jar)](https://github.com/purejava/keepassxc-cryptomator/releases/latest/download/keepassxc-cryptomator-${project.version}.jar)
        
        - xxx
    """.trimIndent()
    releaseAssets.from(
        fileTree("${layout.buildDirectory.get()}/libs") {
            include(
                "keepassxc-cryptomator-${project.version}.jar",
                "keepassxc-cryptomator-${project.version}.jar.asc",
            )
        }
    )
}
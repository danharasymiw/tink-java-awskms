workspace(name = "tink_java_awskms")

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

http_archive(
    name = "tink_java",
    urls = ["https://github.com/tink-crypto/tink-java/archive/main.zip"],
    strip_prefix = "tink-java-main",
)

load("@tink_java//:tink_java_deps.bzl", "tink_java_deps", "TINK_MAVEN_ARTIFACTS")
tink_java_deps()

load("@tink_java//:tink_java_deps_init.bzl", "tink_java_deps_init")
load("@tink_java_awskms//:tink_java_awskms_deps.bzl", "TINK_JAVA_AWSKMS_MAVEN_ARTIFACTS")
load("@rules_jvm_external//:defs.bzl", "maven_install")

tink_java_deps_init()

maven_install(
    artifacts = TINK_MAVEN_ARTIFACTS + TINK_JAVA_AWSKMS_MAVEN_ARTIFACTS,
    repositories = [
        "https://maven.google.com",
        "https://repo1.maven.org/maven2",
    ],
)

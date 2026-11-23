# OpenPortal project notes

## APK certificate helper

`tools\ExtractApkCert.class` is intentionally committed so the launcher can read APK signing certificates with the bundled JRE. Do not delete it as a build artifact.

If `tools\ExtractApkCert.java` changes, rebuild the class before committing:

    javac --release 11 -cp <apksig jar> -d tools tools\ExtractApkCert.java

`deps\` is not committed, so the jar has to come from somewhere already on the machine: `deps\apksig.jar` once the launcher has downloaded it, or an installed Android SDK's `build-tools\<version>\lib\apksigner.jar`.

Rebuilding needs a JDK. The bundled Java is a JRE and cannot compile.

# CgroupV1Logger

This tool injects logging into cgroup V1 initialization process.
In a customer incident report, an NPE raised occasionally when scaling containerized apps on Cloudfoundry.
The app was probably using PlatformMBean to monitor platform information.
The stack trace showed as follows:

```
2024-08-08T15:07:30.00+0200 [APP/PROC/WEB/8] OUT java.lang.NullPointerException: null
2024-08-08T15:07:30.00+0200 [APP/PROC/WEB/8] OUT at java.base/java.util.Objects.requireNonNull(Unknown Source) ~[na:na]
2024-08-08T15:07:30.00+0200 [APP/PROC/WEB/8] OUT at java.base/sun.nio.fs.UnixFileSystem.getPath(Unknown Source) ~[na:na]
2024-08-08T15:07:30.00+0200 [APP/PROC/WEB/8] OUT at java.base/java.nio.file.Path.of(Unknown Source) ~[na:na]
2024-08-08T15:07:30.00+0200 [APP/PROC/WEB/8] OUT at java.base/java.nio.file.Paths.get(Unknown Source) ~[na:na]
2024-08-08T15:07:30.00+0200 [APP/PROC/WEB/8] OUT at java.base/jdk.internal.platform.CgroupUtil.lambda$readStringValue$1(Unknown Source) ~[na:na]
2024-08-08T15:07:30.00+0200 [APP/PROC/WEB/8] OUT at java.base/java.security.AccessController.doPrivileged(Unknown Source) ~[na:na]
2024-08-08T15:07:30.00+0200 [APP/PROC/WEB/8] OUT at java.base/jdk.internal.platform.CgroupUtil.readStringValue(Unknown Source) ~[na:na]
2024-08-08T15:07:30.00+0200 [APP/PROC/WEB/8] OUT at java.base/jdk.internal.platform.CgroupSubsystemController.getStringValue(Unknown Source) ~[na:na]
2024-08-08T15:07:30.00+0200 [APP/PROC/WEB/8] OUT at java.base/jdk.internal.platform.CgroupSubsystemController.getLongValue(Unknown Source) ~[na:na]
2024-08-08T15:07:30.00+0200 [APP/PROC/WEB/8] OUT at java.base/jdk.internal.platform.cgroupv1.CgroupV1Subsystem.getLongValue(Unknown Source) ~[na:na]
```

It looks like the guest platform is using a cgroup V1 environment that is misconfigured, perhaps it is falsely detected as V1 by JDK.
The similar issue is filed under https://bugs.openjdk.org/browse/JDK-8286212.
The tool prints the cgroup V1 information to `/dev/stdout`, that can be helpful to confirm it's the same issue, and that it will be sufficient to apply the same fix (as JDK-8286212).

## Building
### Gradle
To build on linux (mac and Windows are not tested)
```
./gradlew build
```

This will generate `build/libs/a.jar`

## Running

Run a self test, in which the agent is injected into own process from a forked process:
```
java -jar build/libs/a.jar --self-test
```

Produce agent.jar (re-export itself from memory):
```
java -cp build/libs/a.jar CgroupV1Logger --agent-jar > a.jar
```

Dump the current system's cgroupv1 configuration:
```
java -jar a.jar
```

### Running the static agent

Run diagnostic agent with any app:
```
java -javaagent:a.jar -cp .:<YOUR_APP_CLASSPATH> <YOUR_APP_BOOT_CLASS>
```

Alternatively, inject an agent into a running JVM process(es) with PID(s):
```
java -jar a.jar <PID> [<PID2> <PID3> ...]
```

## Known issues

The most frequent issue is the wrong Java version to run the program.
```
$ java -jar a.jar
Error: A JNI error has occurred, please check your installation and try again
Exception in thread "main" java.lang.UnsupportedClassVersionError: CgroupV1Logger has been compiled by a more recent version of the Java Runtime 
(class file version 61.0), this version of the Java Runtime only recognizes class file versions up to 52.0
        at java.lang.ClassLoader.defineClass1(Native Method)
        at java.lang.ClassLoader.defineClass(ClassLoader.java:756)
        at java.security.SecureClassLoader.defineClass(SecureClassLoader.java:142)
        at java.net.URLClassLoader.defineClass(URLClassLoader.java:473)
        at java.net.URLClassLoader.access$100(URLClassLoader.java:74)
```
Make sure you are running at least Java 17.


In the case when the security manager is enabled in the target app, you will see an error like this:
```
java.security.AccessControlException: access denied ("java.lang.RuntimePermission" "accessClassInPackage.jdk.internal.platform.cgroupv1")
        at java.base/java.security.AccessControlContext.checkPermission(AccessControlContext.java:485)
        at java.base/java.security.AccessController.checkPermission(AccessController.java:1068)
        at java.base/java.lang.SecurityManager.checkPermission(SecurityManager.java:416)
        at java.base/java.lang.SecurityManager.checkPackageAccess(SecurityManager.java:1332)
        at java.base/jdk.internal.loader.ClassLoaders$AppClassLoader.loadClass(ClassLoaders.java:184)
        at java.base/java.lang.ClassLoader.loadClass(ClassLoader.java:520)
        at java.base/java.lang.Class.forName0(Native Method)
        at java.base/java.lang.Class.forName(Class.java:375)
        at CgroupV1Logger.agentmain(CgroupV1Logger.java:137)
```
or even
```
Exception in thread "main" java.lang.ClassCircularityError: java/lang/Module$ReflectionData
        at java.base/java.lang.Module.isReflectivelyExportedOrOpen(Module.java:688)
        at java.base/java.lang.Module.implIsExportedOrOpen(Module.java:634)
        at java.base/java.lang.Module.isExported(Module.java:583)
        at java.base/sun.invoke.util.VerifyAccess.isClassAccessible(VerifyAccess.java:212)
        at java.base/java.lang.invoke.MethodHandles$Lookup.isClassAccessible(MethodHandles.java:3697)
        at java.base/java.lang.invoke.MethodHandles$Lookup.resolveOrNull(MethodHandles.java:3663)
        at java.base/java.lang.invoke.MethodHandles$Lookup.canBeCached(MethodHandles.java:4188)
        at java.base/java.lang.invoke.MethodHandles$Lookup.linkMethodHandleConstant(MethodHandles.java:4154)
        at java.base/java.lang.invoke.MethodHandleNatives.linkMethodHandleConstant(MethodHandleNatives.java:615)
        at java.base/sun.net.www.protocol.jrt.JavaRuntimeURLConnection.<clinit>(JavaRuntimeURLConnection.java:56)
        at java.base/sun.net.www.protocol.jrt.Handler.openConnection(Handler.java:42)
        ...
        at java.base/java.lang.System.getLogger(System.java:1769)
        at java.management/com.sun.jmx.remote.util.ClassLogger.<init>(ClassLogger.java:38)
        at java.management/javax.management.NotificationBroadcasterSupport.<clinit>(NotificationBroadcasterSupport.java:365)
        at java.management/javax.management.MBeanServerDelegate.<init>(MBeanServerDelegate.java:73)
        at java.management/com.sun.jmx.mbeanserver.MBeanServerDelegateImpl.<init>(MBeanServerDelegateImpl.java:100)
        at java.management/com.sun.jmx.mbeanserver.JmxMBeanServer.newMBeanServerDelegate(JmxMBeanServer.java:1374)
        at java.management/javax.management.MBeanServerBuilder.newMBeanServerDelegate(MBeanServerBuilder.java:66)
        at java.management/javax.management.MBeanServerFactory.newMBeanServer(MBeanServerFactory.java:321)
        at java.management/javax.management.MBeanServerFactory.createMBeanServer(MBeanServerFactory.java:231)
        at java.management/javax.management.MBeanServerFactory.createMBeanServer(MBeanServerFactory.java:192)
        at java.management/java.lang.management.ManagementFactory.getPlatformMBeanServer(ManagementFactory.java:484)
```
This will require restarting your application with corresponding policy enabled.
An example of permissions required (at minimum):
```
grant {
    permission "javax.management.MBeanServerPermission" "createMBeanServer";
    permission "java.lang.RuntimePermission" "accessClassInPackage.jdk.internal.platform.cgroupv1";
};
```

The exact set of permissions required will depend on the App.

Another issue can be related to App's startup mode:
```
Injecting agent.jar into pid=12345
com.sun.tools.attach.AttachNotSupportedException: The VM does not support the attach mechanism
Error: agent couldn't be loaded into JVM process PID '12345'        
```
This means attaching agents is disabled by `-XX:+DisableAttachMechanism` setting.
Restart the App without using `-XX:+DisableAttachMechanism` setting.


# CgroupV1Logger

This tool injects logging into cgroupsv1 initialization.
In a customer incident report, an NPE raised occasionally when scaling containerized apps on Cloudfoundry.
The app was prabably using PlatformMBean to monitor platform information.
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

that led us to a conclusion that the guest platform is using a cgroupv1 env that is in a way misconfigured.
The issue could be related to https://bugs.openjdk.org/browse/JDK-8286212.
The tool was developed to dump the cgroupv1 information
in the target system, to confirm it's the same issue, and that it will be sufficient to apply the same fix for it.

## Building
### Gradle
To build on linux (mac and Windows are not tested)
```
./gradlew build
```

This will generate `build/libs/a.jar`

## Running

Run a self test:
```
java -jar build/libs/a.jar --self-test
```

Produce (re-export SELF) Agent.jar:
```
java -jar build/libs/a.jar --agent-jar > a.jar
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

### Testing the agent
See above the self test mode, in which an agent is injected into SELF from a forked process.
```
java -jar a.jar --self-test
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
Exception in thread "main" java.security.AccessControlException: access denied 
("javax.management.MBeanServerPermission" "createMBeanServer")
        at java.base/java.security.AccessControlContext.checkPermission(AccessControlContext.java:485)
        at java.base/java.security.AccessController.checkPermission(AccessController.java:1068)
        at java.base/java.lang.SecurityManager.checkPermission(SecurityManager.java:416)
        at java.management/java.lang.management.ManagementFactory.getPlatformMBeanServer(ManagementFactory.java:480)
        at ApplicationStartup.main(ApplicationStartup.java:519)
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


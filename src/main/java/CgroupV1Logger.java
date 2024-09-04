/*
 * Copyright (c) 2024, BELLSOFT. All rights reserved.
 *
 * BELLSOFT licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Please contact BELLSOFT, 111 N Market Street, Suite 300, San Jose,
 * CA 95113 USA or visit www.bell-sw.com if you need additional information
 * or have any questions.
 */

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.Instrumentation;
import java.lang.instrument.UnmodifiableClassException;
import java.lang.management.ManagementFactory;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.ProtectionDomain;
import java.util.Base64;
import java.util.Map;
import java.util.Optional;
import java.util.jar.Attributes;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;

import com.sun.tools.attach.VirtualMachine;
import jdk.internal.platform.CgroupInfo;
import jdk.internal.platform.CgroupSubsystemFactory;
import jdk.internal.platform.CgroupSubsystemFactory.CgroupTypeResult;
import jdk.internal.platform.cgroupv1.CgroupV1Subsystem;

/**
 * <p>The logging hotpatch for CgroupV1SubsystemController injects logging in cgroupsv1 initialization.
 *
 * <p>Compile command:
 * <blockquote><pre>
 *     javac --add-exports java.base/jdk.internal.platform=ALL-UNNAMED \
 *         --add-exports java.base/jdk.internal.platform.cgroupv1=ALL-UNNAMED \
 *         CgroupV1Logger.java
 * </pre></blockquote>
 *
 * <p>Produce Agent JAR:
 * <blockquote><pre>
 *     java CgroupV1Logger --agent-jar > a.jar
 * </pre></blockquote>
 *
 * <p>Run command to dump Cgroupv1 configuration (any of the forms below):
 * <blockquote><pre>
 *     java CgroupV1Logger
 *     java -cp a.jar CgroupV1Logger
 * </pre></blockquote>
 *
 * <p>Run self-test:
 * <blockquote><pre>
 *     java CgroupV1Logger --self-test
 *     java -cp a.jar CgroupV1Logger --self-test
 * </pre></blockquote>
 * Inject agent into a running JVM process wit pid $PID:
 * <blockquote><pre>
 *     java -cp a.jar CgroupV1Logger $PID
 * </pre></blockquote>
 *
 * Run agent together with any java command:
 * <blockquote><pre>
 *     java -javaagent:a.jar -cp .:$YOUR_APP_CLASSPATH $YOUR_APP_BOOT_CLASS
 * </pre></blockquote>
 *
 * JDKs internal CgroupV1SubsystemController.setPath method is recompiled in a following form:
 *
 * <blockquote><pre>
 *     public void setPath(String cgroupPath) {
 *         System.out.println("[" +
 *                 ((root == null)? "null" : root) + ", " +
 *                 ((mountPoint == null)? "null" : mountPoint) + "]: " +
 *                 "setting cgv1 controller path to " + ((cgroupPath == null)? "null" : cgroupPath));
 *         if (root != null && cgroupPath != null) {
 *           if (root.equals("/")) {
 *             if (!cgroupPath.equals("/")) {
 *               path = mountPoint + cgroupPath;
 *             }
 *             else {
 *               path = mountPoint;
 *             }
 *           }
 *           else {
 *             if (root.equals(cgroupPath)) {
 *               path = mountPoint;
 *             }
 *             else {
 *               if (cgroupPath.startsWith(root)) {
 *                 if (cgroupPath.length() &gt; root.length()) {
 *                   String cgroupSubstr = cgroupPath.substring(root.length());
 *                   path = mountPoint + cgroupSubstr;
 *                 }
 *               }
 *             }
 *           }
 *         }
 *         System.out.println("[" +
 *                 ((root == null)? "null" : root) + ", " +
 *                 ((mountPoint == null)? "null" : mountPoint) + "]: " +
 *                 "cgv1 controller path is set to " + ((path == null)? "null" : path));
 *     }
 * </pre></blockquot
 *
 * Tested w/Java 17 (affected by JDK-8286212)
 * 
 * @author sercher
 */
public class CgroupV1Logger {

  public static void premain(String args, Instrumentation inst) {
    agentmain(args, inst);
  }

  public static void agentmain(String args, Instrumentation inst) {

    // preload the target class
    try {
      Class.forName("jdk.internal.platform.cgroupv1.CgroupV1SubsystemController");
      System.out.println("Class jdk.internal.platform.cgroupv1.CgroupV1SubsystemController preloaded.");
    } catch (Exception ignore) {
      System.out.println("WARNING: unable to preload the class:");
      ignore.printStackTrace(System.out);
    }

    byte[] classFile = Base64.getDecoder().decode(PatchedClass.patchedClass.getBytes());

    ClassFileTransformer transformer = new ClassFileTransformer() {
      @Override
      public byte[] transform(ClassLoader loader, String className, Class<?> classBeingRedefined, ProtectionDomain protectionDomain, byte[] classfileBuffer) {
        if (className.equals("jdk/internal/platform/cgroupv1/CgroupV1SubsystemController")) {
          System.out.println("RETRANSFORM: " + className);
          // inject the base64 decoded class
          return classFile;
        } else {
          // leave the class as-is (the wrong class)
          return classfileBuffer;
        }
      }
    };

    inst.addTransformer(transformer, true);

    for (Class c : inst.getAllLoadedClasses()) {
      if ("jdk.internal.platform.cgroupv1.CgroupV1SubsystemController".equals(c.getName())) {
        System.out.println("Patching " + c + " (" + c.getClassLoader() + ")");
        try {
          inst.retransformClasses(c);
        } catch (UnmodifiableClassException uce) {
          System.out.println(uce);
        } catch (Exception e) {
          Throwable t = e.getCause();
          if (t != null) {
            System.out.print(t.getMessage());
          }
        }
      }
    }
  }

  private static String clsName = CgroupV1Logger.class.getName();

  private static void writeAgent(String fileName, boolean deleteOnExit) throws Exception {
    String[] jarClasses = new String[] {
            clsName, clsName + "$1",
            "PatchedClass"
    }; // self and the inner class (transformer)
    Manifest m = new Manifest();
    m.getMainAttributes().put(Attributes.Name.MANIFEST_VERSION, "1.0");
    m.getMainAttributes().put(new Attributes.Name("Main-Class"), clsName);
    m.getMainAttributes().put(new Attributes.Name("Agent-Class"), clsName);
    m.getMainAttributes().put(new Attributes.Name("Premain-Class"), clsName);
    m.getMainAttributes().put(new Attributes.Name("Can-Redefine-Classes"), "true");
    m.getMainAttributes().put(new Attributes.Name("Can-Retransform-Classes"), "true");
    File jarFile = new File(fileName);
    if (deleteOnExit) {
      jarFile.deleteOnExit();
    }
    JarOutputStream js = new JarOutputStream(new FileOutputStream(jarFile), m);
    for (String className : jarClasses) {
      byte[] buf = getClassFromClassLoader(className);
      js.putNextEntry(new JarEntry(className + ".class"));
      js.write(buf);
    }
    js.close();
  }

  private static void loadAgent(String[] pids) throws Exception {
    File tmpJarFile = File.createTempFile("agent", "jar");
    writeAgent(tmpJarFile.getAbsolutePath(), true);
    for (String pid : pids) {
      if (pid != null) {
        try {
          VirtualMachine vm = VirtualMachine.attach(pid);
          vm.loadAgent(tmpJarFile.getAbsolutePath());
        } catch (Exception e) {
          System.out.println(e);
          System.out.println("Error: agent couldn't be loaded into JVM process PID '" + pid + "'");
          System.out.println("Usage: " + CgroupV1Logger.class.getName() + " [ <pid> | --self-test | --agent-jar | --help ]");
          continue;
        }
        System.out.println("Agent loaded into JVM process " + pid);
      }
    }
  }

  private static byte[] getClassFromClassLoader(String className) throws Exception {
    int len;
    InputStream is = Class.forName(className).getClassLoader().getResourceAsStream(className + ".class");
    byte[] buf = new byte[4096];
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    while ((len = is.read(buf)) != -1) {
      baos.write(buf, 0, len);
    }
    return baos.toByteArray();
  }

  public static void selfTestNegative() throws Exception {
    String proc_self_mountinfo =
        "941 931 0:36 /user.slice/user-1000.slice/session-50.scope /sys/fs/cgroup/memory ro,nosuid,nodev,noexec,relatime - cgroup cgroup rw,seclabel,memory\n";
    String proc_cgroups =
        "#subsys_name hierarchy   num_cgroups enabled\n" +
        "memory  2   90  1\n";
    String proc_self_cgroup =
        "9:memory:/user.slice/user-1000.slice/session-3.scope\n";

    String currentDir = System.getProperty("user.dir");

    Path selfCgroups = Paths.get(currentDir, "cgroups_controller");
    Files.writeString(selfCgroups,proc_cgroups);

    Path selfMountInfo = Paths.get(currentDir, "mount_info");
    Files.writeString(selfMountInfo,proc_self_mountinfo);

    Path procSelfCgroup = Paths.get(currentDir, "self_cgroups");
    Files.writeString(procSelfCgroup,proc_self_cgroup);

    String cgroups = selfCgroups.toString();
    String mountInfo = selfMountInfo.toString();
    String selfCgroup = procSelfCgroup.toString();

    selfTestWithParams(mountInfo, cgroups, selfCgroup, false);
  }
  public static void selfTest() throws Exception {
    String currentDir = System.getProperty("user.dir");

    Path cgroupv1CgroupsOnlyCPUCtrl = Paths.get(currentDir, "cgroups_controller");
    Files.writeString(cgroupv1CgroupsOnlyCPUCtrl,
            "#subsys_name hierarchy num_cgroups enabled\n" +
            "cpu\t4\t153\t1\n" +
            "cpuacct\t4\t153\t1\n");

    Path cgroupv1MountInfoCgroupsOnlyCPUCtrl = Paths.get(currentDir, "mount_info");
    Files.writeString(cgroupv1MountInfoCgroupsOnlyCPUCtrl,
            "30 23 0:26 / /sys/fs/cgroup ro,nosuid,nodev,noexec shared:4 - tmpfs tmpfs ro,seclabel,mode=755\n" +
            "40 30 0:36 / /sys/fs/cgroup/cpu,cpuacct rw,nosuid,nodev,noexec,relatime shared:12 - cgroup none rw,seclabel,cpu,cpuacct\n");

    Path cgroupv1SelfCgroupsOnlyCPUCtrl = Paths.get(currentDir, "self_cgroups");
    Files.writeString(cgroupv1SelfCgroupsOnlyCPUCtrl,
            "4:cpu,cpuacct:/user.slice/user-1000.slice/session-3.scope\n");

    String cgroups = cgroupv1CgroupsOnlyCPUCtrl.toString();
    String mountInfo = cgroupv1MountInfoCgroupsOnlyCPUCtrl.toString();
    String selfCgroup = cgroupv1SelfCgroupsOnlyCPUCtrl.toString();

    selfTestWithParams(mountInfo, cgroups, selfCgroup, true);
  }
  private static boolean selfTestFailed = false;
  public static void selfTestWithParams(String mountInfo, String cgroups, String selfCgroup, boolean isPositive) {
    try {
      Optional<CgroupTypeResult> result = CgroupSubsystemFactory.determineType(mountInfo, cgroups, selfCgroup);

      if (!result.isPresent()) {
        System.out.println("CGV1TEST: unable to determine the cgroups interface type");
        selfTestFailed = true;
      }
      CgroupTypeResult res = result.get();
      if (res.isCgroupV2()) {
        System.out.println("CGV1TEST: cgroup V2 unexpected");
        selfTestFailed = true;
      }
      Map<String, CgroupInfo> infos = res.getInfos();
      if (infos.get("memory") != null) {
        if (isPositive) {
          System.out.println("CGV1TEST: memory cgroup unexpected");
          selfTestFailed = true;
        } else {
          CgroupInfo memoryInfo = infos.get("memory");
          if (!"/user.slice/user-1000.slice/session-3.scope".equals(memoryInfo.getCgroupPath())) {
            System.out.println("CGV1TEST: memory cgroup path is wrong");
            selfTestFailed = true;
          }
          if (!"/sys/fs/cgroup/memory".equals(memoryInfo.getMountPoint())) {
            System.out.println("CGV1TEST: memory cgroup mount point is wrong");
            selfTestFailed = true;
          }
          Object o = Class.forName("jdk.internal.platform.cgroupv1.CgroupV1SubsystemController")
                  .getDeclaredConstructor(new Class[]{String.class, String.class})
                  .newInstance(new Object[]{memoryInfo.getMountRoot(), memoryInfo.getMountPoint()});
          o.getClass()
                  .getDeclaredMethod("setPath", new Class[]{String.class})
                  .invoke(o, new Object[]{memoryInfo.getCgroupPath()});
          if (o.getClass().getDeclaredMethod("path", new Class[0]).invoke(o) == null) {
            System.out.println("CGV1TEST: memory cgroup self test passed. JDK version is VULNERABLE");
          } else {
            System.out.println("CGV1TEST: memory cgroup self test passed. JDK version is PATCHED");
          }
        }
      }
      if (infos.get("cpu") == null && isPositive) {
        System.out.println("CGV1TEST: cpu must be non-null");
        selfTestFailed = true;
      }
      if (infos.get("cpu") != null && !isPositive) {
        System.out.println("CGV1TEST: cpu is unexpected");
        selfTestFailed = true;
      }
      CgroupV1Subsystem subsystem = CgroupV1Subsystem.getInstance(infos);
      try {
        long val = subsystem.getMemoryAndSwapLimit();
        if (val != -1) {
          System.out.println("CGV1TEST: expected no limit");
          selfTestFailed = true;
        }
        val = subsystem.getMemoryAndSwapFailCount();
        if (val != -1) {
          System.out.println("CGV1TEST: expected no limit");
          selfTestFailed = true;
        }
        val = subsystem.getMemoryAndSwapMaxUsage();
        if (val != -1) {
          System.out.println("CGV1TEST: expected no limit");
          selfTestFailed = true;
        }
        val = subsystem.getMemoryAndSwapUsage();
        if (val != -1) {
          System.out.println("CGV1TEST: expected no limit");
          selfTestFailed = true;
        }
      } catch (Exception e) {
        System.out.println("CGV1TEST: exception while reading limits:");
        e.printStackTrace(System.out);
        selfTestFailed = true;
      }
    } catch (Exception e) {
      System.out.println("CGV1TEST: exception determining the cgroup type:");
      e.printStackTrace(System.out);
      selfTestFailed = true;
    }
    if (!isPositive && !selfTestFailed) {
      System.out.println("CGV1TEST: all tests passed.");
    }
  }

  public static void main(String args[]) throws Exception {

    String javaHome = System.getProperty("java.home");
    String javaClassPath = System.getProperty("java.class.path");
    boolean isSelfTest = System.getProperty("self.test") != null;

    String pid[];

    if (args.length == 1 && "--agent-jar".equals(args[0])) {
      writeAgent("/dev/stdout", false);
      return;
    } else if (args.length == 1 && "--self-test".equals(args[0])) {
      ProcessBuilder builder = new ProcessBuilder(
          Path.of(javaHome,"bin","java").toString(),
          "-cp", javaClassPath,
          "--add-exports", "java.base/jdk.internal.platform=ALL-UNNAMED",
          "--add-exports", "java.base/jdk.internal.platform.cgroupv1=ALL-UNNAMED",
          "-Dself.test",
          CgroupV1Logger.class.getName()
      );
      System.out.println("Forking a Self Test: '" + builder.command() + "'");
      Process process = builder.start();
      BufferedReader output = new BufferedReader(new InputStreamReader(process.getInputStream()));
      process.waitFor();
      output.lines().forEach(System.out::println);
      return;
    } else if (args.length == 0) {

      long myPid = ProcessHandle.current().pid();
      ProcessBuilder builder = new ProcessBuilder(
          Path.of(javaHome,"bin","java").toString(),
          "-cp", javaClassPath,
          CgroupV1Logger.class.getName(),
          Long.toString(myPid)
      );
      System.out.println("Launching injector '" + builder.command());
      Process process = builder.start();
      BufferedReader output = new BufferedReader(new InputStreamReader(process.getInputStream()));
      process.waitFor();
      output.lines().forEach(System.out::println);
      if(isSelfTest) {
        selfTest();
        selfTestNegative();
      } else {
        ManagementFactory.getPlatformMBeanServer();
      }
      return;
    } else if (args.length == 1 && ("-h".equals(args[0]) || "-help".equals(args[0]) || "--help".equals(args[0]))) {
      System.out.println("usage: " + CgroupV1Logger.class.getName() + " [ <pid> | --self-test | --agent-jar | --help ]");
      return;
    } else {
      pid = args;
    }
    System.out.println("Injecting agent.jar into pid=" + args[0]);
    loadAgent(pid);
  }
}

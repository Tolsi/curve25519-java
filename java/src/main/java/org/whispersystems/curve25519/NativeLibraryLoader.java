package org.whispersystems.curve25519;

import java.io.*;
import java.lang.reflect.Method;
import java.net.URL;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;

/**
 * Used to find and load a JNI library, eventually after having extracted it.
 * <p>
 * It will search for the library in order at the following locations:
 * <ol>
 * <li> system library path: This is where the JVM looks for JNI libraries by default.
 * <li> classpath path: If the JNI library can be found on the classpath, it will get extracted
 * and then loaded. This way you can embed your JNI libraries into your packaged JAR files.
 * They are looked up as resources in this order:
 *   <ol>
 *   <li> "<code>META-INF/native/${platform}/${arch}/${library}</code>": Store your library here if you want to embed
 *   more than one platform JNI library on different processor archs in the jar.
 *   <li> "<code>META-INF/native/${platform}/${library}</code>": Store your library here if you want to embed more
 *   than one platform JNI library in the jar.
 *   <li> "<code>META-INF/native/${os}/${library}</code>": Store your library here if you want to embed more
 *   than one platform JNI library in the jar but don't want to take bit model into account.
 *   <li> "<code>META-INF/native/${library}</code>": Store your library here if your JAR is only going to embedding one
 *   platform library.
 *   </ol>
 * The file extraction is attempted until it succeeds in the following directories.
 *   <ol>
 *   <li> The directory pointed to by the "<code>library.${name}.path</code>" System property (if set)
 *   <li> a temporary directory (uses the "<code>java.io.tmpdir</code>" System property)
 *   </ol>
 * </ol>
 * <p>
 * where:
 * <ul>
 * <li>"<code>${name}</code>" is the name of library
 * <li>"<code>${os}</code>" is your operating system, for example "<code>osx</code>", "<code>linux</code>", or "<code>windows</code>"</li>
 * <li>"<code>${bit-model}</code>" is "<code>64</code>" if the JVM process is a 64 bit process, otherwise it's "<code>32</code>" if the
 * JVM is a 32 bit process</li>
 * <li>"<code>${arch}</code>" is the architecture for the processor, for example "<code>amd64</code>" or "<code>sparcv9</code>"</li>
 * <li>"<code>${platform}</code>" is "<code>${os}${bit-model}</code>", for example "<code>linux32</code>" or "<code>osx64</code>" </li>
 * <li>"<code>${library}</code>": is the normal jni library name for the platform suffix.
 *   For example "<code>${name}.dll</code>" on
 *   windows, "<code>lib${name}.dylib</code>" on OS X, and "<code>lib${name}.so</code>" on linux</li>
 * </ul>
 *
 * @author <a href="http://hiramchirino.com">Hiram Chirino</a>
 * @see <a href="http://fusesource.github.io/hawtjni/">original source code</a>
 * @see System#mapLibraryName(String)
 */
public class NativeLibraryLoader {

    static final private String STRATEGY_SHA1 = "sha1";
    static final private String STRATEGY_TEMP = "temp";

    static final private String STRATEGY = "windows".equals(getOperatingSystem()) ? STRATEGY_SHA1 : STRATEGY_TEMP;

    final private String name;
    final private ClassLoader classLoader;
    private boolean loaded;

    public static void loadLibrary(String name, Class<?> clazz) {
        new NativeLibraryLoader(name, clazz).load();
    }

    public static String getOperatingSystem() {
        String name = System.getProperty("os.name").toLowerCase().trim();
        if (name.startsWith("linux")) {
            return "linux";
        }
        if (name.startsWith("mac os x")) {
            return "osx";
        }
        if (name.startsWith("win")) {
            return "windows";
        }
        return name.replaceAll("\\W+", "_");
    }

    public static String getPlatform() {
        return getOperatingSystem() + getBitModel();
    }

    public static int getBitModel() {
        String prop = System.getProperty("sun.arch.data.model");
        if (prop == null) {
            prop = System.getProperty("com.ibm.vm.bitmode");
        }
        if (prop != null) {
            return Integer.parseInt(prop);
        }
        // GraalVM support, see https://github.com/fusesource/jansi/issues/162
        String arch = System.getProperty("os.arch");
        if (arch.endsWith("64") && "Substrate VM".equals(System.getProperty("java.vm.name"))) {
            return 64;
        }
        return -1; // we don't know..
    }

    private NativeLibraryLoader(String name, Class<?> clazz) {
        if (name == null) {
            throw new IllegalArgumentException("name cannot be null");
        }
        this.name = name;
        this.classLoader = clazz.getClassLoader();
    }

    synchronized private void load() {
        if (loaded) {
            return;
        }
        doLoad();
        loaded = true;
    }

    private void doLoad() {
        ArrayList<Throwable> errors = new ArrayList<>();

        List<String> specificDirs = getSpecificSearchDirs();
        String libFilename = map(name);

        /* Try loading library from java library path */
        if (loadLibrary(errors, name)) {
            return;
        }

        /* Try extracting the library from the jar */
        if (classLoader != null) {
            for (String dir : specificDirs) {
                if (extractAndLoad(errors, dir, libFilename)) {
                    return;
                }
            }
        }

        /* Failed to find the library */
        UnsatisfiedLinkError e = new UnsatisfiedLinkError("Could not load library. Reasons: " + errors.toString());
        try {
            Method method = Throwable.class.getMethod("addSuppressed", Throwable.class);
            for (Throwable t : errors) {
                method.invoke(e, t);
            }
        } catch (Throwable ignore) {
        }
        throw e;
    }

    private List<String> getSpecificSearchDirs() {
        String arch = System.getProperty("os.arch");
        String platform = getPlatform();
        String os = getOperatingSystem();

        List<String> dirs = new ArrayList<>();
        dirs.add(platform + "/" + arch);
        dirs.add(platform);
        dirs.add(os);
        dirs.add(".");
        if (arch.equals("x86_64")) {
            dirs.add(platform + "/amd64");
        }
        return dirs;
    }

    private boolean extractAndLoad(ArrayList<Throwable> errors, String dir, String libName) {
        String resourcePath = "META-INF/native/" + (dir == null ? "" : (dir + '/')) + libName;
        URL resource = classLoader.getResource(resourcePath);
        if (resource != null) {

            int idx = libName.lastIndexOf('.');
            String prefix = libName.substring(0, idx) + "-";
            String suffix = libName.substring(idx);

            for (File path : Arrays.asList(
                    file(System.getProperty("java.io.tmpdir")),
                    file(System.getProperty("user.home"), ".curve25519", name))) {
                if (path != null) {
                    File target;
                    if (STRATEGY_SHA1.equals(STRATEGY)) {
                        target = extractSha1(errors, resource, prefix, suffix, path);
                    } else {
                        target = extractTemp(errors, resource, prefix, suffix, path);
                    }
                    if (target != null) {
                        if (load(errors, target)) {
                            return true;
                        }
                    }
                }
            }
        }
        return false;
    }

    private File file(String... paths) {
        File rc = null;
        for (String path : paths) {
            if (rc == null) {
                rc = new File(path);
            } else if (path != null) {
                rc = new File(rc, path);
            }
        }
        return rc;
    }

    private String map(String libName) {
        libName = System.mapLibraryName(libName);
        String ext = ".jnilib";
        if (libName.endsWith(ext)) {
            libName = libName.substring(0, libName.length() - ext.length()) + ".dylib";
        }
        return libName;
    }

    private File extractSha1(ArrayList<Throwable> errors, URL source, String prefix, String suffix, File directory) {
        File target = null;
        directory = directory.getAbsoluteFile();
        if (!directory.exists()) {
            if (!directory.mkdirs()) {
                errors.add(new IOException("Unable to create directory: " + directory));
                return null;
            }
        }
        try {
            String sha1 = computeSha1(source.openStream());
            String sha1f = "";
            target = new File(directory, prefix + sha1 + suffix);

            if (target.isFile() && target.canRead()) {
                sha1f = computeSha1(new FileInputStream(target));
            }
            if (sha1f.equals(sha1)) {
                return target;
            }

            FileOutputStream os = null;
            InputStream is = null;
            try {
                is = source.openStream();
                if (is != null) {
                    byte[] buffer = new byte[4096];
                    os = new FileOutputStream(target);
                    int read;
                    while ((read = is.read(buffer)) != -1) {
                        os.write(buffer, 0, read);
                    }
                    chmod755(target);
                }
                return target;
            } finally {
                close(os);
                close(is);
            }
        } catch (Throwable e) {
            IOException io;
            if (target != null) {
                target.delete();
                io = new IOException("Unable to extract library from " + source + " to " + target);
            } else {
                io = new IOException("Unable to create temporary file in " + directory);
            }
            io.initCause(e);
            errors.add(io);
        }
        return null;
    }

    private String computeSha1(InputStream is) throws NoSuchAlgorithmException, IOException {
        String sha1;
        try {
            MessageDigest mDigest = MessageDigest.getInstance("SHA1");
            int read;
            byte[] buffer = new byte[4096];
            while ((read = is.read(buffer)) != -1) {
                mDigest.update(buffer, 0, read);
            }
            byte[] result = mDigest.digest();
            StringBuilder sb = new StringBuilder();
            for (byte b : result) {
                sb.append(Integer.toString((b & 0xff) + 0x100, 16).substring(1));
            }
            sha1 = sb.toString();
        } finally {
            close(is);
        }
        return sha1;
    }

    private File extractTemp(ArrayList<Throwable> errors, URL source, String prefix, String suffix, File directory) {
        File target = null;
        directory = directory.getAbsoluteFile();
        if (!directory.exists()) {
            if (!directory.mkdirs()) {
                errors.add(new IOException("Unable to create directory: " + directory));
                return null;
            }
        }
        try {
            FileOutputStream os = null;
            InputStream is = null;
            try {
                target = File.createTempFile(prefix, suffix, directory);
                is = source.openStream();
                if (is != null) {
                    byte[] buffer = new byte[4096];
                    os = new FileOutputStream(target);
                    int read;
                    while ((read = is.read(buffer)) != -1) {
                        os.write(buffer, 0, read);
                    }
                    chmod755(target);
                }
                target.deleteOnExit();
                return target;
            } finally {
                close(os);
                close(is);
            }
        } catch (Throwable e) {
            IOException io;
            if (target != null) {
                target.delete();
                io = new IOException("Unable to extract library from " + source + " to " + target);
            } else {
                io = new IOException("Unable to create temporary file in " + directory);
            }
            io.initCause(e);
            errors.add(io);
        }
        return null;
    }

    static private void close(Closeable file) {
        if (file != null) {
            try {
                file.close();
            } catch (Exception ignore) {
            }
        }
    }

    private void chmod755(File file) {
        if (getPlatform().startsWith("windows")) {
            return;
        }
        // Use Files.setPosixFilePermissions if we are running Java 7+ to avoid forking the JVM for executing chmod
        try {
            ClassLoader classLoader = getClass().getClassLoader();
            // Check if the PosixFilePermissions exists in the JVM, if not this will throw a ClassNotFoundException
            Class<?> posixFilePermissionsClass = classLoader.loadClass("java.nio.file.attribute.PosixFilePermissions");
            // Set <PosixFilePermission> permissionSet = PosixFilePermissions.fromString("rwxr-xr-x")
            Method fromStringMethod = posixFilePermissionsClass.getMethod("fromString", String.class);
            Object permissionSet = fromStringMethod.invoke(null, "rwxr-xr-x");
            // Path path = file.toPath()
            Object path = file.getClass().getMethod("toPath").invoke(file);
            // Files.setPosixFilePermissions(path, permissionSet)
            Class<?> pathClass = classLoader.loadClass("java.nio.file.Path");
            Class<?> filesClass = classLoader.loadClass("java.nio.file.Files");
            Method setPosixFilePermissionsMethod = filesClass.getMethod("setPosixFilePermissions", pathClass, Set.class);
            setPosixFilePermissionsMethod.invoke(null, path, permissionSet);
        } catch (Throwable ignored) {
            // Fallback to starting a new process
            try {
                Runtime.getRuntime().exec(new String[]{"chmod", "755", file.getCanonicalPath()}).waitFor();
            } catch (Throwable e) {
                // NOP
            }
        }
    }

    private boolean load(ArrayList<Throwable> errors, File lib) {
        try {
            System.load(lib.getPath());
            return true;
        } catch (UnsatisfiedLinkError e) {
            LinkageError le = new LinkageError("Unable to load library from " + lib);
            le.initCause(e);
            errors.add(le);
        }
        return false;
    }

    private boolean loadLibrary(ArrayList<Throwable> errors, String lib) {
        try {
            System.loadLibrary(lib);
            return true;
        } catch (UnsatisfiedLinkError e) {
            LinkageError le = new LinkageError("Unable to load library " + lib);
            le.initCause(e);
            errors.add(le);
        }
        return false;
    }
}
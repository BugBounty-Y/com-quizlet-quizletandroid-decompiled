package com.comscore.util.setup;

import androidx.camera.camera2.internal.AbstractC0147y;
import com.comscore.util.ObfuscationChecker;
import com.comscore.util.jni.JniComScoreHelper;
import com.comscore.util.log.Logger;

/* loaded from: classes.dex */
public class Setup {
    static final String a = "comScore";
    private static JniComScoreHelper b = null;
    private static PlatformSetup c = null;
    private static boolean d = false;
    private static boolean e;
    private static final Object f = new Object();

    private static void a() {
        String analyticsVersionNative = getAnalyticsVersionNative();
        String javaCodeVersion = c.getJavaCodeVersion();
        if (analyticsVersionNative == null) {
            Logger.e("Unable to retrieve the native version.");
        } else if (!analyticsVersionNative.equals(javaCodeVersion)) {
            throw new IllegalStateException(AbstractC0147y.e("The version of the comScore java code (", javaCodeVersion, ") and the native library (", analyticsVersionNative, ") are different. Check which version of the comScore SDK is being used."));
        }
    }

    private static boolean b() {
        if (!c.shouldLoadCppLibrary()) {
            Logger.e("Unsupported platform", new RuntimeException("This platform is not supported. The comScore native library will not be loaded."));
            return false;
        }
        PlatformSetup platformSetup = c;
        String str = a;
        String strBuildNativeLibraryName = platformSetup.buildNativeLibraryName(a);
        if (strBuildNativeLibraryName != null) {
            str = strBuildNativeLibraryName;
        }
        String strBuildNativeLibraryPath = c.buildNativeLibraryPath(str);
        if (strBuildNativeLibraryPath != null) {
            try {
                if (strBuildNativeLibraryPath.length() == 0) {
                    System.loadLibrary(str);
                } else {
                    System.load(strBuildNativeLibraryPath);
                }
            } catch (UnsatisfiedLinkError e2) {
                if (strBuildNativeLibraryPath != null && strBuildNativeLibraryPath.length() != 0) {
                    str = strBuildNativeLibraryPath;
                }
                Logger.e("Error loading the native library: ".concat(str), e2);
                return false;
            }
        } else {
            System.loadLibrary(str);
        }
        configureNative(b);
        return true;
    }

    private static native void configureNative(JniComScoreHelper jniComScoreHelper);

    private static native String getAnalyticsVersionNative();

    public static JniComScoreHelper getJniComScoreHelper() {
        return b;
    }

    public static PlatformSetup getPlatformSetup() {
        return c;
    }

    public static boolean isNativeLibrarySuccessfullyLoaded() {
        return e;
    }

    public static boolean isSetUpFinished() {
        return d;
    }

    public static void setUp() {
        if (d) {
            return;
        }
        synchronized (f) {
            try {
                if (!d) {
                    if (new ObfuscationChecker().isCodeObfuscated()) {
                        throw new IllegalStateException("comScore SDK has been obfuscated. Did you add in your proguard-project.txt the following lines?\n-keep class com.comscore.** { *; }\n-dontwarn com.comscore.**");
                    }
                    CustomPlatformSetup customPlatformSetup = new CustomPlatformSetup();
                    c = customPlatformSetup;
                    b = customPlatformSetup.createApplicationInfoHelper();
                    Logger.log = c.createLogger();
                    boolean zB = b();
                    e = zB;
                    d = true;
                    if (zB) {
                        a();
                        Logger.syncrhonizeLogLevelWithNative();
                    }
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }
}

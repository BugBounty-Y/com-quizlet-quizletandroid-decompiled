package com.amazon.device.ads;

import android.util.Log;
import androidx.camera.camera2.internal.AbstractC0147y;

/* loaded from: classes.dex */
public class DtbLog {
    private static final String DEBUG_ERROR = "DTBERROR::";
    private static boolean androidLogAvailable = false;
    private static boolean isCallerInfoEnabled = false;
    private static final Object listenerLock;
    private static DTBLogLevel logLevel = null;
    private static DtbLogListener logListener = null;
    private static final String sdkName = "Amazon DTB Ads API";

    static {
        try {
            Log.isLoggable("1234", 7);
            androidLogAvailable = true;
        } catch (Throwable unused) {
            androidLogAvailable = false;
        }
        listenerLock = new Object();
        isCallerInfoEnabled = false;
        logLevel = DTBLogLevel.Warn;
    }

    public static void debug(String str) {
        if (logLevel.intValue() > DTBLogLevel.Debug.intValue() || !androidLogAvailable) {
            return;
        }
        getTag();
    }

    public static void debugError(String str) {
        if (logLevel.intValue() > DTBLogLevel.Debug.intValue() || !androidLogAvailable) {
            return;
        }
        getTag();
    }

    public static void enableCallerInfo(boolean z) {
        isCallerInfoEnabled = z;
    }

    public static void error(String str) {
        if (logLevel.intValue() > DTBLogLevel.Error.intValue() || !androidLogAvailable) {
            return;
        }
        Log.e(getTag(), str);
    }

    public static void fatal(String str, String str2) {
        int iIntValue = logLevel.intValue();
        DTBLogLevel dTBLogLevel = DTBLogLevel.Fatal;
        if (iIntValue > dTBLogLevel.intValue() || !androidLogAvailable) {
            return;
        }
        Log.e(str, str2);
        postMessageToListener(str, dTBLogLevel, str2);
    }

    private static String getCallerInfo() {
        StackTraceElement stackTraceElement;
        if (!isCallerInfoEnabled) {
            return sdkName;
        }
        StackTraceElement[] stackTrace = Thread.currentThread().getStackTrace();
        if (stackTrace != null) {
            int i = 0;
            while (i < stackTrace.length) {
                String className = stackTrace[i].getClassName();
                if (className.startsWith("dalvik") || className.startsWith("java")) {
                    i++;
                } else {
                    int i2 = i + 2;
                    if (i2 < stackTrace.length) {
                        i = i2;
                    }
                    stackTraceElement = stackTrace[i];
                }
            }
            stackTraceElement = null;
        } else {
            stackTraceElement = null;
        }
        if (stackTraceElement == null) {
            return sdkName;
        }
        return stackTraceElement.getClassName() + ":" + stackTraceElement.getMethodName() + ":" + stackTraceElement.getLineNumber();
    }

    private static String getTag() {
        return isCallerInfoEnabled ? getCallerInfo() : sdkName;
    }

    public static void info(String str) {
        if (logLevel.intValue() > DTBLogLevel.Info.intValue() || !androidLogAvailable) {
            return;
        }
        Log.i(getTag(), str);
    }

    private static void postMessageToListener(String str, DTBLogLevel dTBLogLevel, String str2) {
        if (logListener == null) {
            return;
        }
        synchronized (listenerLock) {
            try {
                DtbLogListener dtbLogListener = logListener;
                if (dtbLogListener != null && str.equals(dtbLogListener.getTag())) {
                    logListener.postMessage(dTBLogLevel, str2);
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public static void setLogLevel(DTBLogLevel dTBLogLevel) {
        logLevel = dTBLogLevel;
    }

    public static void warn(String str) {
        if (logLevel.intValue() > DTBLogLevel.Warn.intValue() || !androidLogAvailable) {
            return;
        }
        Log.w(getTag(), str);
    }

    public static void debug(String str, String str2) {
        int iIntValue = logLevel.intValue();
        DTBLogLevel dTBLogLevel = DTBLogLevel.Debug;
        if (iIntValue > dTBLogLevel.intValue() || !androidLogAvailable) {
            return;
        }
        postMessageToListener(str, dTBLogLevel, str2);
    }

    public static void debugError(String str, String str2) {
        int iIntValue = logLevel.intValue();
        DTBLogLevel dTBLogLevel = DTBLogLevel.Debug;
        if (iIntValue > dTBLogLevel.intValue() || !androidLogAvailable) {
            return;
        }
        postMessageToListener(str, dTBLogLevel, AbstractC0147y.d(DEBUG_ERROR, str2));
    }

    public static void error(String str, String str2) {
        int iIntValue = logLevel.intValue();
        DTBLogLevel dTBLogLevel = DTBLogLevel.Error;
        if (iIntValue > dTBLogLevel.intValue() || !androidLogAvailable) {
            return;
        }
        Log.e(str, str2);
        postMessageToListener(str, dTBLogLevel, str2);
    }

    public static void info(String str, String str2) {
        int iIntValue = logLevel.intValue();
        DTBLogLevel dTBLogLevel = DTBLogLevel.Info;
        if (iIntValue > dTBLogLevel.intValue() || !androidLogAvailable) {
            return;
        }
        Log.i(str, str2);
        postMessageToListener(str, dTBLogLevel, str2);
    }

    public static void warn(String str, String str2) {
        int iIntValue = logLevel.intValue();
        DTBLogLevel dTBLogLevel = DTBLogLevel.Warn;
        if (iIntValue > dTBLogLevel.intValue() || !androidLogAvailable) {
            return;
        }
        Log.w(str, str2);
        postMessageToListener(str, dTBLogLevel, str2);
    }

    public static void fatal(String str) {
        if (logLevel.intValue() > DTBLogLevel.Fatal.intValue() || !androidLogAvailable) {
            return;
        }
        Log.e(getTag(), str);
    }

    public static void fatal(String str, Exception exc) {
        if (logLevel.intValue() > DTBLogLevel.Fatal.intValue() || !androidLogAvailable) {
            return;
        }
        Log.e(getTag(), str, exc);
    }

    public static void fatal(String str, String str2, Exception exc) {
        int iIntValue = logLevel.intValue();
        DTBLogLevel dTBLogLevel = DTBLogLevel.Fatal;
        if (iIntValue > dTBLogLevel.intValue() || !androidLogAvailable) {
            return;
        }
        Log.e(str, str2, exc);
        postMessageToListener(str, dTBLogLevel, str2);
    }
}

package com.pubmatic.sdk.common.log;

import android.app.Application;
import android.content.Context;
import androidx.annotation.Keep;
import androidx.camera.camera2.internal.AbstractC0147y;
import com.pubmatic.sdk.common.a;
import com.pubmatic.sdk.common.utility.o;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Locale;

@Keep
/* loaded from: classes2.dex */
public class POBLog {
    private static volatile POBLog sSelf;
    private final ArrayList<POBLogging> loggers = new ArrayList<>();
    private a.EnumC0007a mLogLevel = a.EnumC0007a.Warn;

    @Keep
    public static class POBLogMessage {
        static final String PMSDK_TAG = "OpenWrapSDK: ";
        final a.EnumC0007a mLogLevel;
        final String mMsg;
        final String mTAG;

        public POBLogMessage(String str, String str2, a.EnumC0007a enumC0007a) {
            this.mTAG = AbstractC0147y.d(PMSDK_TAG, str);
            this.mMsg = str2;
            this.mLogLevel = enumC0007a;
        }
    }

    @Keep
    public interface POBLogging {
        void log(POBLogMessage pOBLogMessage);
    }

    private POBLog() {
    }

    public static void addLogger(POBLogging pOBLogging) {
        getInstance().addLoggerInternal(pOBLogging);
    }

    private void addLoggerInternal(POBLogging pOBLogging) {
        this.loggers.add(pOBLogging);
    }

    public static ArrayList<POBLogging> allLoggers() {
        return getInstance().allLoggersInternal();
    }

    private ArrayList<POBLogging> allLoggersInternal() {
        return this.loggers;
    }

    public static void debug(String str, String str2, Object... objArr) {
        getInstance().log(str, a.EnumC0007a.Debug, str2, objArr);
    }

    public static void error(String str, String str2, Object... objArr) {
        getInstance().log(str, a.EnumC0007a.Error, str2, objArr);
    }

    private static Context getApplicationContext() {
        Application application;
        try {
            application = (Application) Class.forName("android.app.ActivityThread").getMethod("currentApplication", null).invoke(null, null);
        } catch (Exception unused) {
            application = null;
        }
        if (application != null) {
            return application.getApplicationContext();
        }
        return null;
    }

    private static POBLog getInstance() {
        Boolean bool;
        if (sSelf == null) {
            synchronized (POBLog.class) {
                try {
                    if (sSelf == null) {
                        sSelf = new POBLog();
                        sSelf.addLoggerInternal(new POBDefaultLogger());
                        Context applicationContext = getApplicationContext();
                        if (applicationContext != null && (bool = (Boolean) o.getBuildConfigValue(applicationContext, "DEBUG")) != null && bool.booleanValue()) {
                            sSelf.mLogLevel = a.EnumC0007a.Debug;
                        }
                    }
                } finally {
                }
            }
        }
        return sSelf;
    }

    public static a.EnumC0007a getLogLevel() {
        return getInstance().mLogLevel;
    }

    public static void info(String str, String str2, Object... objArr) {
        getInstance().log(str, a.EnumC0007a.Info, str2, objArr);
    }

    private void log(String str, a.EnumC0007a enumC0007a, String str2, Object... objArr) {
        String strL;
        if (enumC0007a.getLevel() >= this.mLogLevel.getLevel()) {
            try {
                strL = String.format(Locale.US, str2, objArr);
            } catch (Exception unused) {
                Locale locale = Locale.US;
                strL = android.support.v4.media.session.a.l(str2, " ", Arrays.toString(objArr));
            }
            POBLogMessage pOBLogMessage = new POBLogMessage(str, strL, enumC0007a);
            for (int i = 0; i < this.loggers.size(); i++) {
                this.loggers.get(i).log(pOBLogMessage);
            }
        }
    }

    public static void setLogLevel(a.EnumC0007a enumC0007a) {
        getInstance().mLogLevel = enumC0007a;
    }

    public static void verbose(String str, String str2, Object... objArr) {
        getInstance().log(str, a.EnumC0007a.Verbose, str2, objArr);
    }

    public static void warn(String str, String str2, Object... objArr) {
        getInstance().log(str, a.EnumC0007a.Warn, str2, objArr);
    }
}

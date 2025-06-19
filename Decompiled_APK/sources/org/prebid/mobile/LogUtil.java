package org.prebid.mobile;

import android.util.Log;

/* loaded from: classes3.dex */
public abstract class LogUtil {
    public static int a;
    public static final PrebidLogger b = new LogCatLogger(0);

    public static class LogCatLogger implements PrebidLogger {
        public /* synthetic */ LogCatLogger(int i) {
            this();
        }

        private LogCatLogger() {
        }
    }

    public interface PrebidLogger {
    }

    public static void a(String str) {
        b("PrebidMobile", str);
    }

    public static void b(String str, String str2) {
        e(6, str, str2);
    }

    public static void c(Throwable th) {
        if (6 >= a) {
            PrebidLogger prebidLogger = b;
            String strD = d("JsScriptsDownloader");
            ((LogCatLogger) prebidLogger).getClass();
            Log.e(strD, "Can't download scripts", th);
        }
    }

    public static String d(String str) {
        StringBuilder sb = new StringBuilder();
        if (str.startsWith("Prebid")) {
            sb.append(str);
        } else {
            sb.append("Prebid");
            sb.append(str);
        }
        return sb.length() > 23 ? sb.substring(0, 22) : sb.toString();
    }

    public static void e(int i, String str, String str2) {
        if (str2 != null && i >= a) {
            PrebidLogger prebidLogger = b;
            String strD = d(str);
            ((LogCatLogger) prebidLogger).getClass();
            Log.println(i, strD, str2);
        }
    }
}

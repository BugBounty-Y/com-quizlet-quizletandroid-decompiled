package org.prebid.mobile.rendering.utils.helpers;

import android.content.Context;
import android.content.pm.PackageManager;
import android.util.Log;
import org.prebid.mobile.LogUtil;

/* loaded from: classes3.dex */
public abstract class AppInfoManager {
    public static String a;
    public static String b;
    public static String c;
    public static String d;

    public static String a(String str) {
        if (str == null || str.length() == 0) {
            return "";
        }
        char cCharAt = str.charAt(0);
        if (Character.isUpperCase(cCharAt)) {
            return str;
        }
        return Character.toUpperCase(cCharAt) + str.substring(1);
    }

    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:13:0x004a -> B:15:0x005f). Please report as a decompilation issue!!! */
    public static void b(Context context) {
        if (b == null || c == null) {
            try {
                b = context.getPackageName();
                c = "(unknown)";
                try {
                    PackageManager packageManager = context.getPackageManager();
                    c = (String) packageManager.getApplicationLabel(packageManager.getApplicationInfo(b, 0));
                    d = packageManager.getPackageInfo(b, 0).versionName;
                } catch (Exception e) {
                    LogUtil.b("AppInfoManager", "Failed to get app name: " + Log.getStackTraceString(e));
                }
            } catch (Exception e2) {
                LogUtil.b("AppInfoManager", "Failed to get package name: " + Log.getStackTraceString(e2));
            }
        }
    }
}

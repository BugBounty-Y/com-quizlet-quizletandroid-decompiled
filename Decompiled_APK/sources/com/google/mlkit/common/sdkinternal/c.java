package com.google.mlkit.common.sdkinternal;

import android.content.Context;
import android.content.pm.PackageManager;
import android.util.Log;

/* loaded from: classes2.dex */
public abstract class c {
    public static final com.quizlet.data.repository.widget.b a = new com.quizlet.data.repository.widget.b("CommonUtils", "");

    public static String a(Context context) {
        try {
            return String.valueOf(context.getPackageManager().getPackageInfo(context.getPackageName(), 0).versionCode);
        } catch (PackageManager.NameNotFoundException e) {
            String strConcat = "Exception thrown when trying to get app version ".concat(e.toString());
            com.quizlet.data.repository.widget.b bVar = a;
            if (!Log.isLoggable((String) bVar.b, 6)) {
                return "";
            }
            Log.e("CommonUtils", bVar.t(strConcat));
            return "";
        }
    }
}

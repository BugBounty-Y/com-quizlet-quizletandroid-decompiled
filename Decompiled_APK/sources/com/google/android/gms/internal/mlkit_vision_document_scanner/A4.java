package com.google.android.gms.internal.mlkit_vision_document_scanner;

import android.app.ActivityManager;
import android.app.Application;
import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import com.quizlet.quizletandroid.ui.deeplinkinterstitial.DeepLinkInterstitialActivity;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class A4 {
    public static boolean a(Application context) {
        Intrinsics.checkNotNullParameter(context, "context");
        try {
            Object systemService = context.getSystemService("activity");
            Intrinsics.e(systemService, "null cannot be cast to non-null type android.app.ActivityManager");
            List<ActivityManager.RunningAppProcessInfo> runningAppProcesses = ((ActivityManager) systemService).getRunningAppProcesses();
            if (runningAppProcesses == null) {
                return false;
            }
            String packageName = context.getPackageName();
            Intrinsics.checkNotNullExpressionValue(packageName, "getPackageName(...)");
            for (ActivityManager.RunningAppProcessInfo runningAppProcessInfo : runningAppProcesses) {
                if (runningAppProcessInfo.importance == 100 && Intrinsics.b(runningAppProcessInfo.processName, packageName)) {
                    return true;
                }
            }
            return false;
        } catch (Exception unused) {
            return true;
        }
    }

    public static Intent b(Context context, String canonicalUrl) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(canonicalUrl, "canonicalUrl");
        Intent intent = new Intent(context, (Class<?>) DeepLinkInterstitialActivity.class);
        intent.setAction("android.intent.action.VIEW");
        intent.setData(Uri.parse(canonicalUrl));
        return intent;
    }
}

package com.braze.support;

import android.content.Context;
import android.content.pm.PackageManager;
import android.os.Build;
import com.braze.support.BrazeLogger;
import com.google.android.gms.common.GoogleApiAvailability;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class k {
    public static final k a = new k();

    public static final boolean a(Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        int iC = GoogleApiAvailability.d.c(context, com.google.android.gms.common.c.a);
        if (iC == 0) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) a, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new v(21), 7, (Object) null);
            return true;
        }
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) a, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new com.braze.enums.i(iC, 16), 7, (Object) null);
        return false;
    }

    public static final String b() {
        return "Google Play Services is available.";
    }

    public static final String c() {
        return "Unexpected exception while checking for com.google.android.gsf";
    }

    public static final boolean b(Context context) throws PackageManager.NameNotFoundException {
        Intrinsics.checkNotNullParameter(context, "context");
        try {
            if (Build.VERSION.SDK_INT >= 33) {
                context.getPackageManager().getPackageInfo("com.google.android.gsf", PackageManager.PackageInfoFlags.of(0L));
                return true;
            }
            context.getPackageManager().getPackageInfo("com.google.android.gsf", 0);
            return true;
        } catch (PackageManager.NameNotFoundException unused) {
            return false;
        } catch (Exception e) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) a, BrazeLogger.Priority.W, (Throwable) e, false, (Function0) new v(20), 4, (Object) null);
            return false;
        }
    }

    public static final String a(int i) {
        return android.support.v4.media.session.a.f(i, "Google Play Services is unavailable. Connection result: ");
    }
}

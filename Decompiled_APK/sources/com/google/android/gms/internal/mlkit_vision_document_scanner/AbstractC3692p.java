package com.google.android.gms.internal.mlkit_vision_document_scanner;

import android.content.Context;
import android.content.pm.PackageManager;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;

/* renamed from: com.google.android.gms.internal.mlkit_vision_document_scanner.p, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3692p {
    public static Boolean a;
    public static final /* synthetic */ int b = 0;

    public static boolean a(Context context) {
        Boolean bool = a;
        if (bool != null) {
            return bool.booleanValue();
        }
        try {
            boolean z = context.getPackageManager().getApplicationInfo(context.getPackageName(), 128).metaData.getBoolean("firebase_performance_logcat_enabled", false);
            a = Boolean.valueOf(z);
            return z;
        } catch (PackageManager.NameNotFoundException | NullPointerException e) {
            com.google.firebase.perf.logging.a aVarD = com.google.firebase.perf.logging.a.d();
            e.getMessage();
            aVarD.a();
            return false;
        }
    }

    public static int b(long j) {
        if (j > 2147483647L) {
            return SubsamplingScaleImageView.TILE_SIZE_AUTO;
        }
        if (j < -2147483648L) {
            return Integer.MIN_VALUE;
        }
        return (int) j;
    }
}

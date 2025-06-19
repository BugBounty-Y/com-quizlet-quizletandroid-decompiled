package com.google.android.gms.internal.ads;

import android.app.AppOpsManager;
import android.content.Context;
import android.os.Build;
import java.util.concurrent.Executor;

/* renamed from: com.google.android.gms.internal.ads.f5, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2039f5 {
    public static final String[] e = {"android:establish_vpn_service", "android:establish_vpn_manager"};
    public long a;
    public long b;
    public long c;
    public boolean d;

    public static C2039f5 a(Context context, Executor executor) {
        String[] strArr = e;
        C2039f5 c2039f5 = new C2039f5();
        c2039f5.a = 0L;
        c2039f5.b = 0L;
        c2039f5.c = -1L;
        c2039f5.d = false;
        if (Build.VERSION.SDK_INT >= 30) {
            try {
                ((AppOpsManager) context.getSystemService("appops")).startWatchingActive(strArr, executor, new C1995e5(c2039f5));
            } catch (IllegalArgumentException | NoSuchMethodError unused) {
            }
        }
        return c2039f5;
    }
}

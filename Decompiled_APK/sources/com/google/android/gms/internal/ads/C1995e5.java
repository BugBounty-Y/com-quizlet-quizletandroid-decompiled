package com.google.android.gms.internal.ads;

import android.app.AppOpsManager$OnOpActiveChangedListener;

/* renamed from: com.google.android.gms.internal.ads.e5, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1995e5 implements AppOpsManager$OnOpActiveChangedListener {
    public final /* synthetic */ C2039f5 a;

    public C1995e5(C2039f5 c2039f5) {
        this.a = c2039f5;
    }

    public final void onOpActiveChanged(String str, int i, String str2, boolean z) {
        if (z) {
            C2039f5 c2039f5 = this.a;
            c2039f5.a = System.currentTimeMillis();
            c2039f5.d = true;
            return;
        }
        C2039f5 c2039f52 = this.a;
        long jCurrentTimeMillis = System.currentTimeMillis();
        long j = c2039f52.b;
        if (j > 0 && jCurrentTimeMillis >= j) {
            c2039f52.c = jCurrentTimeMillis - j;
        }
        c2039f52.d = false;
    }
}

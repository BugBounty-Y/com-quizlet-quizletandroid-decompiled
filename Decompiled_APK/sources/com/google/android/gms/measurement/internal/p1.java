package com.google.android.gms.measurement.internal;

import android.os.SystemClock;

/* loaded from: classes2.dex */
public final class p1 {
    public final String a;
    public final long b;

    public p1(r1 r1Var, String str) {
        this.a = str;
        ((com.google.android.gms.common.util.b) r1Var.f()).getClass();
        this.b = SystemClock.elapsedRealtime();
    }
}

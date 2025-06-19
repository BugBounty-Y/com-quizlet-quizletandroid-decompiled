package com.google.android.gms.internal.ads;

import java.util.concurrent.Executor;

/* renamed from: com.google.android.gms.internal.ads.lv, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2331lv {
    public static final C2331lv d = new C2331lv();
    public final Runnable a;
    public final Executor b;
    public C2331lv c;

    public C2331lv() {
        this.a = null;
        this.b = null;
    }

    public C2331lv(Runnable runnable, Executor executor) {
        this.a = runnable;
        this.b = executor;
    }
}

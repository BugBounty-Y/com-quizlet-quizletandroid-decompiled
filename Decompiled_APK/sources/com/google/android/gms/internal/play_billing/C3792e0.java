package com.google.android.gms.internal.play_billing;

import java.util.concurrent.Executor;

/* renamed from: com.google.android.gms.internal.play_billing.e0, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3792e0 {
    public static final C3792e0 d = new C3792e0();
    public final Runnable a;
    public final Executor b;
    public C3792e0 c;

    public C3792e0() {
        this.a = null;
        this.b = null;
    }

    public C3792e0(Runnable runnable, Executor executor) {
        this.a = runnable;
        this.b = executor;
    }
}

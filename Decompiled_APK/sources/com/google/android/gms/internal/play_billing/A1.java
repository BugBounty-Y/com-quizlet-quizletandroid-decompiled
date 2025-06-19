package com.google.android.gms.internal.play_billing;

import java.util.concurrent.Executor;

/* loaded from: classes2.dex */
public final class A1 {
    public static final A1 d = new A1(null, null);
    public final Runnable a;
    public final Executor b;
    public A1 c;

    public A1(Runnable runnable, Executor executor) {
        this.a = runnable;
        this.b = executor;
    }
}

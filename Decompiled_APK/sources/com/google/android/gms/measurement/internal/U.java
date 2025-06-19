package com.google.android.gms.measurement.internal;

import java.lang.Thread;

/* loaded from: classes2.dex */
public final class U implements Thread.UncaughtExceptionHandler {
    public final String a;
    public final /* synthetic */ X b;

    public U(X x, String str) {
        this.b = x;
        this.a = str;
    }

    @Override // java.lang.Thread.UncaughtExceptionHandler
    public final synchronized void uncaughtException(Thread thread, Throwable th) {
        I i = ((Y) this.b.b).i;
        Y.k(i);
        i.g.g(this.a, th);
    }
}

package com.google.android.gms.internal.ads;

import java.util.concurrent.Callable;
import java.util.concurrent.CancellationException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executor;

/* loaded from: classes2.dex */
public final class Iv extends Vv {
    public final Executor c;
    public final /* synthetic */ Jv d;
    public final Callable e;
    public final /* synthetic */ Jv f;

    public Iv(Jv jv, Callable callable, Executor executor) {
        this.f = jv;
        this.d = jv;
        executor.getClass();
        this.c = executor;
        this.e = callable;
    }

    @Override // com.google.android.gms.internal.ads.Vv
    public final Object a() {
        return this.e.call();
    }

    @Override // com.google.android.gms.internal.ads.Vv
    public final String b() {
        return this.e.toString();
    }

    @Override // com.google.android.gms.internal.ads.Vv
    public final void d(Throwable th) {
        Jv jv = this.d;
        jv.p = null;
        if (th instanceof ExecutionException) {
            jv.h(((ExecutionException) th).getCause());
        } else if (th instanceof CancellationException) {
            jv.cancel(false);
        } else {
            jv.h(th);
        }
    }

    @Override // com.google.android.gms.internal.ads.Vv
    public final void e(Object obj) {
        this.d.p = null;
        this.f.g(obj);
    }

    @Override // com.google.android.gms.internal.ads.Vv
    public final boolean f() {
        return this.d.isDone();
    }
}

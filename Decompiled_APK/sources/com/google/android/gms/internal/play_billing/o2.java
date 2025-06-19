package com.google.android.gms.internal.play_billing;

import java.lang.ref.WeakReference;
import java.util.concurrent.Executor;
import java.util.concurrent.TimeUnit;

/* loaded from: classes2.dex */
public final class o2 implements InterfaceFutureC3845w0 {
    public final WeakReference a;
    public final n2 b = new n2(this);

    public o2(m2 m2Var) {
        this.a = new WeakReference(m2Var);
    }

    @Override // com.google.android.gms.internal.play_billing.InterfaceFutureC3845w0
    public final void b(Runnable runnable, Executor executor) {
        this.b.b(runnable, executor);
    }

    @Override // java.util.concurrent.Future
    public final boolean cancel(boolean z) {
        m2 m2Var = (m2) this.a.get();
        boolean zCancel = this.b.cancel(z);
        if (!zCancel || m2Var == null) {
            return zCancel;
        }
        m2Var.a = null;
        m2Var.b = null;
        m2Var.c.i(null);
        return true;
    }

    @Override // java.util.concurrent.Future
    public final Object get() {
        return this.b.get();
    }

    @Override // java.util.concurrent.Future
    public final boolean isCancelled() {
        return this.b.a instanceof S0;
    }

    @Override // java.util.concurrent.Future
    public final boolean isDone() {
        return this.b.isDone();
    }

    public final String toString() {
        return this.b.toString();
    }

    @Override // java.util.concurrent.Future
    public final Object get(long j, TimeUnit timeUnit) {
        return this.b.get(j, timeUnit);
    }
}

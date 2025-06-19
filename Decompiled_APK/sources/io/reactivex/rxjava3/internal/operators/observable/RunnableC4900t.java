package io.reactivex.rxjava3.internal.operators.observable;

import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

/* renamed from: io.reactivex.rxjava3.internal.operators.observable.t, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class RunnableC4900t extends AtomicReference implements Runnable, io.reactivex.rxjava3.disposables.b {
    public final Object a;
    public final long b;
    public final C4901u c;
    public final AtomicBoolean d = new AtomicBoolean();

    public RunnableC4900t(Object obj, long j, C4901u c4901u) {
        this.a = obj;
        this.b = j;
        this.c = c4901u;
    }

    @Override // io.reactivex.rxjava3.disposables.b
    public final void dispose() {
        io.reactivex.rxjava3.internal.disposables.a.a(this);
    }

    @Override // java.lang.Runnable
    public final void run() {
        if (this.d.compareAndSet(false, true)) {
            C4901u c4901u = this.c;
            long j = this.b;
            Object obj = this.a;
            if (j == c4901u.g) {
                c4901u.a.b(obj);
                io.reactivex.rxjava3.internal.disposables.a.a(this);
            }
        }
    }
}

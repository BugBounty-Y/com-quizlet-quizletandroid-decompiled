package io.reactivex.rxjava3.internal.operators.observable;

import com.google.android.gms.internal.mlkit_vision_barcode.C7;
import java.util.concurrent.TimeUnit;

/* renamed from: io.reactivex.rxjava3.internal.operators.observable.u, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4901u implements io.reactivex.rxjava3.core.l, io.reactivex.rxjava3.disposables.b {
    public final io.reactivex.rxjava3.observers.a a;
    public final long b;
    public final TimeUnit c;
    public final io.reactivex.rxjava3.core.n d;
    public io.reactivex.rxjava3.disposables.b e;
    public RunnableC4900t f;
    public volatile long g;
    public boolean h;

    public C4901u(io.reactivex.rxjava3.observers.a aVar, long j, TimeUnit timeUnit, io.reactivex.rxjava3.core.n nVar) {
        this.a = aVar;
        this.b = j;
        this.c = timeUnit;
        this.d = nVar;
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void a(io.reactivex.rxjava3.disposables.b bVar) {
        if (io.reactivex.rxjava3.internal.disposables.a.f(this.e, bVar)) {
            this.e = bVar;
            this.a.a(this);
        }
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void b(Object obj) {
        if (this.h) {
            return;
        }
        long j = this.g + 1;
        this.g = j;
        RunnableC4900t runnableC4900t = this.f;
        if (runnableC4900t != null) {
            io.reactivex.rxjava3.internal.disposables.a.a(runnableC4900t);
        }
        RunnableC4900t runnableC4900t2 = new RunnableC4900t(obj, j, this);
        this.f = runnableC4900t2;
        io.reactivex.rxjava3.internal.disposables.a.c(runnableC4900t2, this.d.b(runnableC4900t2, this.b, this.c));
    }

    @Override // io.reactivex.rxjava3.disposables.b
    public final void dispose() {
        this.e.dispose();
        this.d.dispose();
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void onComplete() {
        if (this.h) {
            return;
        }
        this.h = true;
        RunnableC4900t runnableC4900t = this.f;
        if (runnableC4900t != null) {
            io.reactivex.rxjava3.internal.disposables.a.a(runnableC4900t);
        }
        if (runnableC4900t != null) {
            runnableC4900t.run();
        }
        this.a.onComplete();
        this.d.dispose();
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void onError(Throwable th) {
        if (this.h) {
            C7.c(th);
            return;
        }
        RunnableC4900t runnableC4900t = this.f;
        if (runnableC4900t != null) {
            io.reactivex.rxjava3.internal.disposables.a.a(runnableC4900t);
        }
        this.h = true;
        this.a.onError(th);
        this.d.dispose();
    }
}

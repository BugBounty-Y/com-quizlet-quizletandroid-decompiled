package io.reactivex.rxjava3.internal.operators.observable;

import com.google.android.gms.internal.mlkit_vision_barcode.C7;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

/* loaded from: classes3.dex */
public final class v0 extends AtomicLong implements io.reactivex.rxjava3.core.l, io.reactivex.rxjava3.disposables.b, w0 {
    public final io.reactivex.rxjava3.core.l a;
    public final long b;
    public final TimeUnit c;
    public final io.reactivex.rxjava3.core.n d;
    public final io.reactivex.rxjava3.disposables.d e;
    public final AtomicReference f;

    public v0(io.reactivex.rxjava3.core.l lVar, io.reactivex.rxjava3.core.n nVar) {
        TimeUnit timeUnit = TimeUnit.SECONDS;
        this.a = lVar;
        this.b = 10L;
        this.c = timeUnit;
        this.d = nVar;
        this.e = new io.reactivex.rxjava3.disposables.d(2);
        this.f = new AtomicReference();
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void a(io.reactivex.rxjava3.disposables.b bVar) {
        io.reactivex.rxjava3.internal.disposables.a.e(this.f, bVar);
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void b(Object obj) {
        long j = get();
        if (j != Long.MAX_VALUE) {
            long j2 = 1 + j;
            if (compareAndSet(j, j2)) {
                io.reactivex.rxjava3.disposables.d dVar = this.e;
                ((io.reactivex.rxjava3.disposables.b) dVar.get()).dispose();
                this.a.b(obj);
                io.reactivex.rxjava3.disposables.b bVarB = this.d.b(new com.google.ads.conversiontracking.i(j2, this), this.b, this.c);
                dVar.getClass();
                io.reactivex.rxjava3.internal.disposables.a.c(dVar, bVarB);
            }
        }
    }

    @Override // io.reactivex.rxjava3.internal.operators.observable.w0
    public final void c(long j) {
        if (compareAndSet(j, Long.MAX_VALUE)) {
            io.reactivex.rxjava3.internal.disposables.a.a(this.f);
            this.a.onError(new TimeoutException(io.reactivex.rxjava3.internal.util.c.c(this.b, this.c)));
            this.d.dispose();
        }
    }

    @Override // io.reactivex.rxjava3.disposables.b
    public final void dispose() {
        io.reactivex.rxjava3.internal.disposables.a.a(this.f);
        this.d.dispose();
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void onComplete() {
        if (getAndSet(Long.MAX_VALUE) != Long.MAX_VALUE) {
            io.reactivex.rxjava3.disposables.d dVar = this.e;
            dVar.getClass();
            io.reactivex.rxjava3.internal.disposables.a.a(dVar);
            this.a.onComplete();
            this.d.dispose();
        }
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void onError(Throwable th) {
        if (getAndSet(Long.MAX_VALUE) == Long.MAX_VALUE) {
            C7.c(th);
            return;
        }
        io.reactivex.rxjava3.disposables.d dVar = this.e;
        dVar.getClass();
        io.reactivex.rxjava3.internal.disposables.a.a(dVar);
        this.a.onError(th);
        this.d.dispose();
    }
}

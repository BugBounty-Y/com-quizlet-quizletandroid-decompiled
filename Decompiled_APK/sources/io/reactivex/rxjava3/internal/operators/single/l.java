package io.reactivex.rxjava3.internal.operators.single;

import com.google.android.gms.internal.mlkit_vision_barcode.C7;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicReference;

/* loaded from: classes3.dex */
public final class l extends AtomicReference implements io.reactivex.rxjava3.core.q, Runnable, io.reactivex.rxjava3.disposables.b {
    public final io.reactivex.rxjava3.core.q a;
    public final AtomicReference b;
    public final io.reactivex.rxjava3.internal.operators.completable.k c;
    public io.reactivex.rxjava3.internal.operators.flowable.b d;
    public final long e;
    public final TimeUnit f;

    public l(io.reactivex.rxjava3.core.q qVar, io.reactivex.rxjava3.internal.operators.flowable.b bVar, long j) {
        TimeUnit timeUnit = TimeUnit.SECONDS;
        this.a = qVar;
        this.d = bVar;
        this.e = j;
        this.f = timeUnit;
        this.b = new AtomicReference();
        if (bVar != null) {
            this.c = new io.reactivex.rxjava3.internal.operators.completable.k(qVar, 2);
        } else {
            this.c = null;
        }
    }

    @Override // io.reactivex.rxjava3.core.q
    public final void a(io.reactivex.rxjava3.disposables.b bVar) {
        io.reactivex.rxjava3.internal.disposables.a.e(this, bVar);
    }

    @Override // io.reactivex.rxjava3.disposables.b
    public final void dispose() {
        io.reactivex.rxjava3.internal.disposables.a.a(this);
        io.reactivex.rxjava3.internal.disposables.a.a(this.b);
        io.reactivex.rxjava3.internal.operators.completable.k kVar = this.c;
        if (kVar != null) {
            io.reactivex.rxjava3.internal.disposables.a.a(kVar);
        }
    }

    @Override // io.reactivex.rxjava3.core.q
    public final void onError(Throwable th) {
        io.reactivex.rxjava3.disposables.b bVar = (io.reactivex.rxjava3.disposables.b) get();
        io.reactivex.rxjava3.internal.disposables.a aVar = io.reactivex.rxjava3.internal.disposables.a.a;
        if (bVar == aVar || !compareAndSet(bVar, aVar)) {
            C7.c(th);
        } else {
            io.reactivex.rxjava3.internal.disposables.a.a(this.b);
            this.a.onError(th);
        }
    }

    @Override // io.reactivex.rxjava3.core.q, com.google.android.gms.tasks.d
    public final void onSuccess(Object obj) {
        io.reactivex.rxjava3.disposables.b bVar = (io.reactivex.rxjava3.disposables.b) get();
        io.reactivex.rxjava3.internal.disposables.a aVar = io.reactivex.rxjava3.internal.disposables.a.a;
        if (bVar == aVar || !compareAndSet(bVar, aVar)) {
            return;
        }
        io.reactivex.rxjava3.internal.disposables.a.a(this.b);
        this.a.onSuccess(obj);
    }

    @Override // java.lang.Runnable
    public final void run() {
        if (io.reactivex.rxjava3.internal.disposables.a.a(this)) {
            io.reactivex.rxjava3.internal.operators.flowable.b bVar = this.d;
            if (bVar == null) {
                this.a.onError(new TimeoutException(io.reactivex.rxjava3.internal.util.c.c(this.e, this.f)));
            } else {
                this.d = null;
                bVar.j(this.c);
            }
        }
    }
}

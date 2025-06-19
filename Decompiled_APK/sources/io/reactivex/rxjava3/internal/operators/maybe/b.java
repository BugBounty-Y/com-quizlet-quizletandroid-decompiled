package io.reactivex.rxjava3.internal.operators.maybe;

import com.google.android.gms.internal.mlkit_vision_barcode.z7;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

/* loaded from: classes3.dex */
public final class b extends AtomicInteger implements io.reactivex.rxjava3.core.h, org.reactivestreams.b {
    public final io.reactivex.rxjava3.core.f a;
    public final io.reactivex.rxjava3.core.g[] e;
    public int f;
    public long g;
    public final AtomicLong b = new AtomicLong();
    public final io.reactivex.rxjava3.disposables.d d = new io.reactivex.rxjava3.disposables.d(2);
    public final AtomicReference c = new AtomicReference(io.reactivex.rxjava3.internal.util.e.a);

    public b(io.reactivex.rxjava3.core.f fVar, io.reactivex.rxjava3.core.g[] gVarArr) {
        this.a = fVar;
        this.e = gVarArr;
    }

    @Override // io.reactivex.rxjava3.core.h
    public final void a(io.reactivex.rxjava3.disposables.b bVar) {
        io.reactivex.rxjava3.disposables.d dVar = this.d;
        dVar.getClass();
        io.reactivex.rxjava3.internal.disposables.a.c(dVar, bVar);
    }

    public final void b() {
        if (getAndIncrement() != 0) {
            return;
        }
        AtomicReference atomicReference = this.c;
        do {
            io.reactivex.rxjava3.disposables.d dVar = this.d;
            if (dVar.b()) {
                atomicReference.lazySet(null);
                return;
            }
            Object obj = atomicReference.get();
            if (obj != null) {
                io.reactivex.rxjava3.internal.util.e eVar = io.reactivex.rxjava3.internal.util.e.a;
                io.reactivex.rxjava3.core.f fVar = this.a;
                if (obj != eVar) {
                    long j = this.g;
                    if (j != this.b.get()) {
                        this.g = j + 1;
                        atomicReference.lazySet(null);
                        fVar.b(obj);
                    }
                } else {
                    atomicReference.lazySet(null);
                }
                if (!dVar.b()) {
                    int i = this.f;
                    io.reactivex.rxjava3.core.g[] gVarArr = this.e;
                    if (i == gVarArr.length) {
                        fVar.onComplete();
                        return;
                    } else {
                        this.f = i + 1;
                        gVarArr[i].e(this);
                    }
                }
            }
        } while (decrementAndGet() != 0);
    }

    @Override // org.reactivestreams.b
    public final void cancel() {
        io.reactivex.rxjava3.disposables.d dVar = this.d;
        dVar.getClass();
        io.reactivex.rxjava3.internal.disposables.a.a(dVar);
    }

    @Override // org.reactivestreams.b
    public final void e(long j) {
        if (io.reactivex.rxjava3.internal.subscriptions.c.c(j)) {
            z7.f(this.b, j);
            b();
        }
    }

    @Override // io.reactivex.rxjava3.core.h
    public final void onComplete() {
        this.c.lazySet(io.reactivex.rxjava3.internal.util.e.a);
        b();
    }

    @Override // io.reactivex.rxjava3.core.h
    public final void onError(Throwable th) {
        this.a.onError(th);
    }

    @Override // io.reactivex.rxjava3.core.h, io.reactivex.rxjava3.core.q, com.google.android.gms.tasks.d
    public final void onSuccess(Object obj) {
        this.c.lazySet(obj);
        b();
    }
}

package io.reactivex.rxjava3.internal.operators.observable;

import com.google.android.gms.internal.mlkit_vision_barcode.x7;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicInteger;

/* loaded from: classes3.dex */
public final class K extends AtomicInteger implements io.reactivex.rxjava3.disposables.b, io.reactivex.rxjava3.core.l {
    public final io.reactivex.rxjava3.core.b a;
    public final io.reactivex.rxjava3.functions.h c;
    public io.reactivex.rxjava3.disposables.b e;
    public volatile boolean f;
    public final io.reactivex.rxjava3.internal.util.b b = new io.reactivex.rxjava3.internal.util.b();
    public final io.reactivex.rxjava3.disposables.a d = new io.reactivex.rxjava3.disposables.a();

    public K(io.reactivex.rxjava3.core.b bVar, io.reactivex.rxjava3.functions.h hVar) {
        this.a = bVar;
        this.c = hVar;
        lazySet(1);
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
        try {
            Object objApply = this.c.apply(obj);
            Objects.requireNonNull(objApply, "The mapper returned a null CompletableSource");
            io.reactivex.rxjava3.core.d dVar = (io.reactivex.rxjava3.core.d) objApply;
            getAndIncrement();
            io.reactivex.rxjava3.internal.operators.maybe.d dVar2 = new io.reactivex.rxjava3.internal.operators.maybe.d(this);
            if (this.f || !this.d.b(dVar2)) {
                return;
            }
            dVar.b(dVar2);
        } catch (Throwable th) {
            x7.b(th);
            this.e.dispose();
            onError(th);
        }
    }

    @Override // io.reactivex.rxjava3.disposables.b
    public final void dispose() {
        this.f = true;
        this.e.dispose();
        this.d.dispose();
        this.b.d();
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void onComplete() {
        if (decrementAndGet() == 0) {
            this.b.e(this.a);
        }
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void onError(Throwable th) {
        if (this.b.c(th)) {
            this.f = true;
            this.e.dispose();
            this.d.dispose();
            this.b.e(this.a);
        }
    }
}

package io.reactivex.rxjava3.internal.operators.observable;

import com.google.android.gms.internal.mlkit_vision_barcode.x7;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

/* loaded from: classes3.dex */
public final class O extends AtomicInteger implements io.reactivex.rxjava3.core.l, io.reactivex.rxjava3.disposables.b {
    public final io.reactivex.rxjava3.core.l a;
    public final io.reactivex.rxjava3.functions.h e;
    public io.reactivex.rxjava3.disposables.b g;
    public volatile boolean h;
    public final io.reactivex.rxjava3.disposables.a b = new io.reactivex.rxjava3.disposables.a();
    public final io.reactivex.rxjava3.internal.util.b d = new io.reactivex.rxjava3.internal.util.b();
    public final AtomicInteger c = new AtomicInteger(1);
    public final AtomicReference f = new AtomicReference();

    public O(io.reactivex.rxjava3.core.l lVar, io.reactivex.rxjava3.functions.h hVar) {
        this.a = lVar;
        this.e = hVar;
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void a(io.reactivex.rxjava3.disposables.b bVar) {
        if (io.reactivex.rxjava3.internal.disposables.a.f(this.g, bVar)) {
            this.g = bVar;
            this.a.a(this);
        }
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void b(Object obj) {
        try {
            Object objApply = this.e.apply(obj);
            Objects.requireNonNull(objApply, "The mapper returned a null SingleSource");
            io.reactivex.rxjava3.core.p pVar = (io.reactivex.rxjava3.core.p) objApply;
            this.c.getAndIncrement();
            io.reactivex.rxjava3.internal.operators.single.c cVar = new io.reactivex.rxjava3.internal.operators.single.c(this);
            if (this.h || !this.b.b(cVar)) {
                return;
            }
            pVar.j(cVar);
        } catch (Throwable th) {
            x7.b(th);
            this.g.dispose();
            onError(th);
        }
    }

    public final void c() {
        io.reactivex.rxjava3.core.l lVar = this.a;
        AtomicInteger atomicInteger = this.c;
        AtomicReference atomicReference = this.f;
        int iAddAndGet = 1;
        while (!this.h) {
            if (((Throwable) this.d.get()) != null) {
                io.reactivex.rxjava3.operators.g gVar = (io.reactivex.rxjava3.operators.g) this.f.get();
                if (gVar != null) {
                    gVar.clear();
                }
                this.d.g(lVar);
                return;
            }
            boolean z = atomicInteger.get() == 0;
            io.reactivex.rxjava3.operators.g gVar2 = (io.reactivex.rxjava3.operators.g) atomicReference.get();
            Object objPoll = gVar2 != null ? gVar2.poll() : null;
            boolean z2 = objPoll == null;
            if (z && z2) {
                this.d.g(this.a);
                return;
            } else if (z2) {
                iAddAndGet = addAndGet(-iAddAndGet);
                if (iAddAndGet == 0) {
                    return;
                }
            } else {
                lVar.b(objPoll);
            }
        }
        io.reactivex.rxjava3.operators.g gVar3 = (io.reactivex.rxjava3.operators.g) this.f.get();
        if (gVar3 != null) {
            gVar3.clear();
        }
    }

    @Override // io.reactivex.rxjava3.disposables.b
    public final void dispose() {
        this.h = true;
        this.g.dispose();
        this.b.dispose();
        this.d.d();
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void onComplete() {
        this.c.decrementAndGet();
        if (getAndIncrement() == 0) {
            c();
        }
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void onError(Throwable th) {
        this.c.decrementAndGet();
        if (this.d.c(th)) {
            this.b.dispose();
            if (getAndIncrement() == 0) {
                c();
            }
        }
    }
}

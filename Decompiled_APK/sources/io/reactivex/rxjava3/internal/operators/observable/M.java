package io.reactivex.rxjava3.internal.operators.observable;

import com.google.android.gms.internal.mlkit_vision_barcode.x7;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

/* loaded from: classes3.dex */
public final class M extends AtomicInteger implements io.reactivex.rxjava3.core.l, io.reactivex.rxjava3.disposables.b {
    public final io.reactivex.rxjava3.core.l a;
    public final boolean b;
    public final io.reactivex.rxjava3.functions.h f;
    public io.reactivex.rxjava3.disposables.b h;
    public volatile boolean i;
    public final io.reactivex.rxjava3.disposables.a c = new io.reactivex.rxjava3.disposables.a();
    public final io.reactivex.rxjava3.internal.util.b e = new io.reactivex.rxjava3.internal.util.b();
    public final AtomicInteger d = new AtomicInteger(1);
    public final AtomicReference g = new AtomicReference();

    public M(io.reactivex.rxjava3.core.l lVar, io.reactivex.rxjava3.functions.h hVar, boolean z) {
        this.a = lVar;
        this.f = hVar;
        this.b = z;
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void a(io.reactivex.rxjava3.disposables.b bVar) {
        if (io.reactivex.rxjava3.internal.disposables.a.f(this.h, bVar)) {
            this.h = bVar;
            this.a.a(this);
        }
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void b(Object obj) {
        try {
            Object objApply = this.f.apply(obj);
            Objects.requireNonNull(objApply, "The mapper returned a null MaybeSource");
            io.reactivex.rxjava3.core.g gVar = (io.reactivex.rxjava3.core.g) objApply;
            this.d.getAndIncrement();
            C4899s c4899s = new C4899s(this);
            if (this.i || !this.c.b(c4899s)) {
                return;
            }
            gVar.e(c4899s);
        } catch (Throwable th) {
            x7.b(th);
            this.h.dispose();
            onError(th);
        }
    }

    public final void c() {
        io.reactivex.rxjava3.core.l lVar = this.a;
        AtomicInteger atomicInteger = this.d;
        AtomicReference atomicReference = this.g;
        int iAddAndGet = 1;
        while (!this.i) {
            if (!this.b && ((Throwable) this.e.get()) != null) {
                io.reactivex.rxjava3.operators.g gVar = (io.reactivex.rxjava3.operators.g) this.g.get();
                if (gVar != null) {
                    gVar.clear();
                }
                this.e.g(lVar);
                return;
            }
            boolean z = atomicInteger.get() == 0;
            io.reactivex.rxjava3.operators.g gVar2 = (io.reactivex.rxjava3.operators.g) atomicReference.get();
            Object objPoll = gVar2 != null ? gVar2.poll() : null;
            boolean z2 = objPoll == null;
            if (z && z2) {
                this.e.g(lVar);
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
        io.reactivex.rxjava3.operators.g gVar3 = (io.reactivex.rxjava3.operators.g) this.g.get();
        if (gVar3 != null) {
            gVar3.clear();
        }
    }

    @Override // io.reactivex.rxjava3.disposables.b
    public final void dispose() {
        this.i = true;
        this.h.dispose();
        this.c.dispose();
        this.e.d();
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void onComplete() {
        this.d.decrementAndGet();
        if (getAndIncrement() == 0) {
            c();
        }
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void onError(Throwable th) {
        this.d.decrementAndGet();
        if (this.e.c(th)) {
            if (!this.b) {
                this.c.dispose();
            }
            if (getAndIncrement() == 0) {
                c();
            }
        }
    }
}

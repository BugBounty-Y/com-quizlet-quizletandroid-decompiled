package io.reactivex.rxjava3.internal.operators.observable;

import java.util.concurrent.atomic.AtomicReference;

/* loaded from: classes3.dex */
public final class F extends AtomicReference implements io.reactivex.rxjava3.core.l {
    public final G a;
    public volatile boolean b;
    public volatile io.reactivex.rxjava3.operators.e c;
    public int d;

    public F(G g) {
        this.a = g;
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void a(io.reactivex.rxjava3.disposables.b bVar) {
        if (io.reactivex.rxjava3.internal.disposables.a.e(this, bVar) && (bVar instanceof io.reactivex.rxjava3.operators.a)) {
            io.reactivex.rxjava3.operators.a aVar = (io.reactivex.rxjava3.operators.a) bVar;
            int iH = aVar.h(7);
            if (iH == 1) {
                this.d = iH;
                this.c = aVar;
                this.b = true;
                this.a.e();
                return;
            }
            if (iH == 2) {
                this.d = iH;
                this.c = aVar;
            }
        }
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void b(Object obj) {
        if (this.d != 0) {
            this.a.e();
            return;
        }
        G g = this.a;
        if (g.get() == 0 && g.compareAndSet(0, 1)) {
            g.a.b(obj);
            if (g.decrementAndGet() == 0) {
                return;
            }
        } else {
            io.reactivex.rxjava3.operators.e gVar = this.c;
            if (gVar == null) {
                gVar = new io.reactivex.rxjava3.operators.g(g.d);
                this.c = gVar;
            }
            gVar.offer(obj);
            if (g.getAndIncrement() != 0) {
                return;
            }
        }
        g.f();
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void onComplete() {
        this.b = true;
        this.a.e();
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void onError(Throwable th) {
        if (this.a.g.c(th)) {
            G g = this.a;
            g.getClass();
            g.d();
            this.b = true;
            this.a.e();
        }
    }
}

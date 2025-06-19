package io.reactivex.rxjava3.internal.operators.observable;

import com.google.android.gms.internal.mlkit_vision_barcode.x7;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicInteger;

/* renamed from: io.reactivex.rxjava3.internal.operators.observable.q, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4898q extends AtomicInteger implements io.reactivex.rxjava3.core.l, io.reactivex.rxjava3.disposables.b {
    public final io.reactivex.rxjava3.core.l a;
    public final com.quizlet.quizletandroid.ui.profile.p b;
    public final int c;
    public final io.reactivex.rxjava3.internal.util.b d;
    public final C4897p e;
    public io.reactivex.rxjava3.operators.e f;
    public io.reactivex.rxjava3.disposables.b g;
    public volatile boolean h;
    public volatile boolean i;
    public volatile boolean j;
    public int k;

    public C4898q(io.reactivex.rxjava3.core.l lVar, int i) {
        com.quizlet.quizletandroid.ui.profile.p pVar = io.reactivex.rxjava3.internal.functions.d.a;
        this.a = lVar;
        this.b = pVar;
        this.c = i;
        this.d = new io.reactivex.rxjava3.internal.util.b();
        this.e = new C4897p(lVar, this);
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void a(io.reactivex.rxjava3.disposables.b bVar) {
        if (io.reactivex.rxjava3.internal.disposables.a.f(this.g, bVar)) {
            this.g = bVar;
            if (bVar instanceof io.reactivex.rxjava3.operators.a) {
                io.reactivex.rxjava3.operators.a aVar = (io.reactivex.rxjava3.operators.a) bVar;
                int iH = aVar.h(3);
                if (iH == 1) {
                    this.k = iH;
                    this.f = aVar;
                    this.i = true;
                    this.a.a(this);
                    c();
                    return;
                }
                if (iH == 2) {
                    this.k = iH;
                    this.f = aVar;
                    this.a.a(this);
                    return;
                }
            }
            this.f = new io.reactivex.rxjava3.operators.g(this.c);
            this.a.a(this);
        }
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void b(Object obj) {
        if (this.k == 0) {
            this.f.offer(obj);
        }
        c();
    }

    public final void c() {
        if (getAndIncrement() != 0) {
            return;
        }
        io.reactivex.rxjava3.core.l lVar = this.a;
        io.reactivex.rxjava3.operators.e eVar = this.f;
        io.reactivex.rxjava3.internal.util.b bVar = this.d;
        while (true) {
            if (!this.h) {
                if (this.j) {
                    eVar.clear();
                    return;
                }
                if (((Throwable) bVar.get()) != null) {
                    eVar.clear();
                    this.j = true;
                    bVar.g(lVar);
                    return;
                }
                boolean z = this.i;
                try {
                    Object objPoll = eVar.poll();
                    boolean z2 = objPoll == null;
                    if (z && z2) {
                        this.j = true;
                        bVar.g(lVar);
                        return;
                    }
                    if (!z2) {
                        try {
                            this.b.getClass();
                            Objects.requireNonNull(objPoll, "The mapper returned a null ObservableSource");
                            io.reactivex.rxjava3.core.k kVar = (io.reactivex.rxjava3.core.k) objPoll;
                            if (kVar instanceof io.reactivex.rxjava3.functions.j) {
                                try {
                                    Object obj = ((io.reactivex.rxjava3.functions.j) kVar).get();
                                    if (obj != null && !this.j) {
                                        lVar.b(obj);
                                    }
                                } catch (Throwable th) {
                                    x7.b(th);
                                    bVar.c(th);
                                }
                            } else {
                                this.h = true;
                                kVar.c(this.e);
                            }
                        } catch (Throwable th2) {
                            x7.b(th2);
                            this.j = true;
                            this.g.dispose();
                            eVar.clear();
                            bVar.c(th2);
                            bVar.g(lVar);
                            return;
                        }
                    }
                } catch (Throwable th3) {
                    x7.b(th3);
                    this.j = true;
                    this.g.dispose();
                    bVar.c(th3);
                    bVar.g(lVar);
                    return;
                }
            }
            if (decrementAndGet() == 0) {
                return;
            }
        }
    }

    @Override // io.reactivex.rxjava3.disposables.b
    public final void dispose() {
        this.j = true;
        this.g.dispose();
        C4897p c4897p = this.e;
        c4897p.getClass();
        io.reactivex.rxjava3.internal.disposables.a.a(c4897p);
        this.d.d();
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void onComplete() {
        this.i = true;
        c();
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void onError(Throwable th) {
        if (this.d.c(th)) {
            this.i = true;
            c();
        }
    }
}

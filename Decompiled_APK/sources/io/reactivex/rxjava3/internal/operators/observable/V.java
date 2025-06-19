package io.reactivex.rxjava3.internal.operators.observable;

import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

/* loaded from: classes3.dex */
public final class V extends AtomicInteger implements io.reactivex.rxjava3.disposables.b, io.reactivex.rxjava3.core.k {
    public final Object a;
    public final io.reactivex.rxjava3.operators.g b;
    public final T c;
    public volatile boolean d;
    public Throwable e;
    public final AtomicBoolean f = new AtomicBoolean();
    public final AtomicReference g = new AtomicReference();
    public final AtomicInteger h = new AtomicInteger();

    public V(int i, T t, Object obj) {
        this.b = new io.reactivex.rxjava3.operators.g(i);
        this.c = t;
        this.a = obj;
    }

    public final void a() {
        if (getAndIncrement() != 0) {
            return;
        }
        io.reactivex.rxjava3.operators.g gVar = this.b;
        io.reactivex.rxjava3.core.l lVar = (io.reactivex.rxjava3.core.l) this.g.get();
        int iAddAndGet = 1;
        while (true) {
            if (lVar != null) {
                while (true) {
                    boolean z = this.d;
                    Object objPoll = gVar.poll();
                    boolean z2 = objPoll == null;
                    boolean z3 = this.f.get();
                    io.reactivex.rxjava3.operators.g gVar2 = this.b;
                    AtomicReference atomicReference = this.g;
                    if (z3) {
                        gVar2.clear();
                        atomicReference.lazySet(null);
                        if ((this.h.get() & 2) == 0) {
                            T t = this.c;
                            t.getClass();
                            Object obj = this.a;
                            if (obj == null) {
                                obj = T.h;
                            }
                            t.e.remove(obj);
                            if (t.decrementAndGet() == 0) {
                                t.f.dispose();
                                return;
                            }
                            return;
                        }
                        return;
                    }
                    if (z) {
                        Throwable th = this.e;
                        if (th != null) {
                            gVar2.clear();
                            atomicReference.lazySet(null);
                            lVar.onError(th);
                            return;
                        } else if (z2) {
                            atomicReference.lazySet(null);
                            lVar.onComplete();
                            return;
                        }
                    }
                    if (z2) {
                        break;
                    } else {
                        lVar.b(objPoll);
                    }
                }
            }
            iAddAndGet = addAndGet(-iAddAndGet);
            if (iAddAndGet == 0) {
                return;
            }
            if (lVar == null) {
                lVar = (io.reactivex.rxjava3.core.l) this.g.get();
            }
        }
    }

    @Override // io.reactivex.rxjava3.core.k
    public final void c(io.reactivex.rxjava3.core.l lVar) {
        AtomicInteger atomicInteger;
        int i;
        do {
            atomicInteger = this.h;
            i = atomicInteger.get();
            if ((i & 1) != 0) {
                io.reactivex.rxjava3.internal.disposables.b.d(new IllegalStateException("Only one Observer allowed!"), lVar);
                return;
            }
        } while (!atomicInteger.compareAndSet(i, i | 1));
        lVar.a(this);
        AtomicReference atomicReference = this.g;
        atomicReference.lazySet(lVar);
        if (this.f.get()) {
            atomicReference.lazySet(null);
        } else {
            a();
        }
    }

    @Override // io.reactivex.rxjava3.disposables.b
    public final void dispose() {
        if (this.f.compareAndSet(false, true) && getAndIncrement() == 0) {
            this.g.lazySet(null);
            if ((this.h.get() & 2) == 0) {
                T t = this.c;
                t.getClass();
                Object obj = this.a;
                if (obj == null) {
                    obj = T.h;
                }
                t.e.remove(obj);
                if (t.decrementAndGet() == 0) {
                    t.f.dispose();
                }
            }
        }
    }
}

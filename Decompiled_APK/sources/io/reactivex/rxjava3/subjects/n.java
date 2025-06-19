package io.reactivex.rxjava3.subjects;

import java.io.Serializable;
import java.util.concurrent.atomic.AtomicReference;

/* loaded from: classes3.dex */
public final class n extends AtomicReference implements l {
    public final int a = 1;
    public int b;
    public volatile k c;
    public k d;
    public volatile boolean e;

    public n() {
        k kVar = new k(null);
        this.d = kVar;
        this.c = kVar;
    }

    @Override // io.reactivex.rxjava3.subjects.l
    public final void a(m mVar) {
        if (mVar.getAndIncrement() != 0) {
            return;
        }
        io.reactivex.rxjava3.core.l lVar = mVar.a;
        k kVar = (k) mVar.c;
        if (kVar == null) {
            kVar = this.c;
        }
        int iAddAndGet = 1;
        while (!mVar.d) {
            k kVar2 = (k) kVar.get();
            if (kVar2 != null) {
                Object obj = kVar2.a;
                if (this.e && kVar2.get() == null) {
                    if (io.reactivex.rxjava3.internal.util.e.a(obj)) {
                        lVar.onComplete();
                    } else {
                        lVar.onError(((io.reactivex.rxjava3.internal.util.d) obj).a);
                    }
                    mVar.c = null;
                    mVar.d = true;
                    return;
                }
                lVar.b(obj);
                kVar = kVar2;
            } else if (kVar.get() != null) {
                continue;
            } else {
                mVar.c = kVar;
                iAddAndGet = mVar.addAndGet(-iAddAndGet);
                if (iAddAndGet == 0) {
                    return;
                }
            }
        }
        mVar.c = null;
    }

    @Override // io.reactivex.rxjava3.subjects.l
    public final void add(Object obj) {
        k kVar = new k(obj);
        k kVar2 = this.d;
        this.d = kVar;
        this.b++;
        kVar2.set(kVar);
        int i = this.b;
        if (i > this.a) {
            this.b = i - 1;
            this.c = (k) this.c.get();
        }
    }

    @Override // io.reactivex.rxjava3.subjects.l
    public final void b(Serializable serializable) {
        k kVar = new k(serializable);
        k kVar2 = this.d;
        this.d = kVar;
        this.b++;
        kVar2.lazySet(kVar);
        k kVar3 = this.c;
        if (kVar3.a != null) {
            k kVar4 = new k(null);
            kVar4.lazySet(kVar3.get());
            this.c = kVar4;
        }
        this.e = true;
    }

    @Override // io.reactivex.rxjava3.subjects.l
    public final Object getValue() {
        k kVar = this.c;
        k kVar2 = null;
        while (true) {
            k kVar3 = (k) kVar.get();
            if (kVar3 == null) {
                break;
            }
            kVar2 = kVar;
            kVar = kVar3;
        }
        Object obj = kVar.a;
        if (obj == null) {
            return null;
        }
        return (io.reactivex.rxjava3.internal.util.e.a(obj) || (obj instanceof io.reactivex.rxjava3.internal.util.d)) ? kVar2.a : obj;
    }
}

package io.reactivex.rxjava3.internal.operators.observable;

import com.google.android.gms.internal.mlkit_vision_barcode.x7;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/* loaded from: classes3.dex */
public final class T extends AtomicInteger implements io.reactivex.rxjava3.core.l, io.reactivex.rxjava3.disposables.b {
    public static final Object h = new Object();
    public final io.reactivex.rxjava3.core.l a;
    public final com.quizlet.infra.legacysyncengine.net.sync.a b;
    public final com.quizlet.quizletandroid.ui.profile.p c;
    public final int d;
    public final ConcurrentHashMap e;
    public io.reactivex.rxjava3.disposables.b f;
    public final AtomicBoolean g;

    public T(io.reactivex.rxjava3.core.l lVar, com.quizlet.infra.legacysyncengine.net.sync.a aVar, int i) {
        com.quizlet.quizletandroid.ui.profile.p pVar = io.reactivex.rxjava3.internal.functions.d.a;
        this.g = new AtomicBoolean();
        this.a = lVar;
        this.b = aVar;
        this.c = pVar;
        this.d = i;
        this.e = new ConcurrentHashMap();
        lazySet(1);
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void a(io.reactivex.rxjava3.disposables.b bVar) {
        if (io.reactivex.rxjava3.internal.disposables.a.f(this.f, bVar)) {
            this.f = bVar;
            this.a.a(this);
        }
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void b(Object obj) {
        boolean z;
        io.reactivex.rxjava3.core.l lVar = this.a;
        try {
            Object objApply = this.b.apply(obj);
            ConcurrentHashMap concurrentHashMap = this.e;
            U u = (U) concurrentHashMap.get(objApply);
            if (u != null) {
                z = false;
            } else {
                if (this.g.get()) {
                    return;
                }
                U u2 = new U(objApply, new V(this.d, this, objApply));
                concurrentHashMap.put(objApply, u2);
                getAndIncrement();
                z = true;
                u = u2;
            }
            try {
                V v = u.b;
                this.c.getClass();
                Objects.requireNonNull(obj, "The value supplied is null");
                v.b.offer(obj);
                v.a();
                if (z) {
                    lVar.b(u);
                    AtomicInteger atomicInteger = v.h;
                    if (atomicInteger.get() == 0 && atomicInteger.compareAndSet(0, 2)) {
                        this.e.remove(objApply);
                        if (decrementAndGet() == 0) {
                            this.f.dispose();
                        }
                        V v2 = u.b;
                        v2.d = true;
                        v2.a();
                    }
                }
            } catch (Throwable th) {
                x7.b(th);
                this.f.dispose();
                if (z) {
                    lVar.b(u);
                }
                onError(th);
            }
        } catch (Throwable th2) {
            x7.b(th2);
            this.f.dispose();
            onError(th2);
        }
    }

    @Override // io.reactivex.rxjava3.disposables.b
    public final void dispose() {
        if (this.g.compareAndSet(false, true) && decrementAndGet() == 0) {
            this.f.dispose();
        }
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void onComplete() {
        ConcurrentHashMap concurrentHashMap = this.e;
        ArrayList arrayList = new ArrayList(concurrentHashMap.values());
        concurrentHashMap.clear();
        Iterator it2 = arrayList.iterator();
        while (it2.hasNext()) {
            V v = ((U) it2.next()).b;
            v.d = true;
            v.a();
        }
        this.a.onComplete();
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void onError(Throwable th) {
        ArrayList arrayList = new ArrayList(this.e.values());
        this.e.clear();
        Iterator it2 = arrayList.iterator();
        while (it2.hasNext()) {
            V v = ((U) it2.next()).b;
            v.e = th;
            v.d = true;
            v.a();
        }
        this.a.onError(th);
    }
}

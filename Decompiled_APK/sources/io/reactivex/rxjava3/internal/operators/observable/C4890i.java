package io.reactivex.rxjava3.internal.operators.observable;

import com.google.android.gms.internal.ads.C2245jv;
import com.google.android.gms.internal.mlkit_vision_barcode.x7;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.concurrent.atomic.AtomicBoolean;

/* renamed from: io.reactivex.rxjava3.internal.operators.observable.i, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4890i extends AtomicBoolean implements io.reactivex.rxjava3.core.l, io.reactivex.rxjava3.disposables.b {
    public final io.reactivex.rxjava3.core.l a;
    public final int b;
    public final int c;
    public final io.reactivex.rxjava3.internal.util.a d;
    public io.reactivex.rxjava3.disposables.b e;
    public final ArrayDeque f;
    public long g;

    public C4890i(io.reactivex.rxjava3.core.l lVar, int i, int i2) {
        io.reactivex.rxjava3.internal.util.a aVar = io.reactivex.rxjava3.internal.util.a.a;
        this.a = lVar;
        this.b = i;
        this.c = i2;
        this.d = aVar;
        this.f = new ArrayDeque();
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
        long j = this.g;
        this.g = 1 + j;
        long j2 = j % this.c;
        ArrayDeque arrayDeque = this.f;
        io.reactivex.rxjava3.core.l lVar = this.a;
        if (j2 == 0) {
            try {
                this.d.getClass();
                ArrayList arrayList = new ArrayList();
                C2245jv c2245jv = io.reactivex.rxjava3.internal.util.c.a;
                arrayDeque.offer(arrayList);
            } catch (Throwable th) {
                x7.b(th);
                arrayDeque.clear();
                this.e.dispose();
                lVar.onError(th);
                return;
            }
        }
        Iterator it2 = arrayDeque.iterator();
        while (it2.hasNext()) {
            Collection collection = (Collection) it2.next();
            collection.add(obj);
            if (this.b <= collection.size()) {
                it2.remove();
                lVar.b(collection);
            }
        }
    }

    @Override // io.reactivex.rxjava3.disposables.b
    public final void dispose() {
        this.e.dispose();
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void onComplete() {
        while (true) {
            ArrayDeque arrayDeque = this.f;
            boolean zIsEmpty = arrayDeque.isEmpty();
            io.reactivex.rxjava3.core.l lVar = this.a;
            if (zIsEmpty) {
                lVar.onComplete();
                return;
            }
            lVar.b(arrayDeque.poll());
        }
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void onError(Throwable th) {
        this.f.clear();
        this.a.onError(th);
    }
}

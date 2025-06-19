package io.reactivex.rxjava3.internal.operators.observable;

import com.google.android.gms.internal.mlkit_vision_barcode.C7;
import com.google.android.gms.internal.mlkit_vision_barcode.x7;

/* renamed from: io.reactivex.rxjava3.internal.operators.observable.z, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4906z extends io.reactivex.rxjava3.internal.observers.b implements io.reactivex.rxjava3.core.l {
    public final io.reactivex.rxjava3.core.l a;
    public final io.reactivex.rxjava3.functions.a b;
    public io.reactivex.rxjava3.disposables.b c;
    public io.reactivex.rxjava3.operators.a d;
    public boolean e;

    public C4906z(io.reactivex.rxjava3.core.l lVar, io.reactivex.rxjava3.functions.a aVar) {
        this.a = lVar;
        this.b = aVar;
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void a(io.reactivex.rxjava3.disposables.b bVar) {
        if (io.reactivex.rxjava3.internal.disposables.a.f(this.c, bVar)) {
            this.c = bVar;
            if (bVar instanceof io.reactivex.rxjava3.operators.a) {
                this.d = (io.reactivex.rxjava3.operators.a) bVar;
            }
            this.a.a(this);
        }
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void b(Object obj) {
        this.a.b(obj);
    }

    @Override // io.reactivex.rxjava3.operators.e
    public final void clear() {
        this.d.clear();
    }

    public final void d() {
        if (compareAndSet(0, 1)) {
            try {
                this.b.run();
            } catch (Throwable th) {
                x7.b(th);
                C7.c(th);
            }
        }
    }

    @Override // io.reactivex.rxjava3.disposables.b
    public final void dispose() {
        this.c.dispose();
        d();
    }

    @Override // io.reactivex.rxjava3.operators.b
    public final int h(int i) {
        io.reactivex.rxjava3.operators.a aVar = this.d;
        if (aVar == null || (i & 4) != 0) {
            return 0;
        }
        int iH = aVar.h(i);
        if (iH != 0) {
            this.e = iH == 1;
        }
        return iH;
    }

    @Override // io.reactivex.rxjava3.operators.e
    public final boolean isEmpty() {
        return this.d.isEmpty();
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void onComplete() {
        this.a.onComplete();
        d();
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void onError(Throwable th) {
        this.a.onError(th);
        d();
    }

    @Override // io.reactivex.rxjava3.operators.e
    public final Object poll() {
        Object objPoll = this.d.poll();
        if (objPoll == null && this.e) {
            d();
        }
        return objPoll;
    }
}

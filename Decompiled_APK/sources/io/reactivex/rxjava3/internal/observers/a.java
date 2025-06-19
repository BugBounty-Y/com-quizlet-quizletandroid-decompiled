package io.reactivex.rxjava3.internal.observers;

import com.google.android.gms.internal.mlkit_vision_barcode.C7;
import io.reactivex.rxjava3.core.l;

/* loaded from: classes3.dex */
public abstract class a implements l, io.reactivex.rxjava3.operators.a {
    public final l a;
    public io.reactivex.rxjava3.disposables.b b;
    public io.reactivex.rxjava3.operators.a c;
    public boolean d;
    public int e;

    public a(l lVar) {
        this.a = lVar;
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void a(io.reactivex.rxjava3.disposables.b bVar) {
        if (io.reactivex.rxjava3.internal.disposables.a.f(this.b, bVar)) {
            this.b = bVar;
            if (bVar instanceof io.reactivex.rxjava3.operators.a) {
                this.c = (io.reactivex.rxjava3.operators.a) bVar;
            }
            this.a.a(this);
        }
    }

    @Override // io.reactivex.rxjava3.operators.e
    public final void clear() {
        this.c.clear();
    }

    @Override // io.reactivex.rxjava3.disposables.b
    public final void dispose() {
        this.b.dispose();
    }

    @Override // io.reactivex.rxjava3.operators.b
    public int h(int i) {
        io.reactivex.rxjava3.operators.a aVar = this.c;
        if (aVar == null || (i & 4) != 0) {
            return 0;
        }
        int iH = aVar.h(i);
        if (iH == 0) {
            return iH;
        }
        this.e = iH;
        return iH;
    }

    @Override // io.reactivex.rxjava3.operators.e
    public final boolean isEmpty() {
        return this.c.isEmpty();
    }

    @Override // io.reactivex.rxjava3.operators.e
    public final boolean offer(Object obj) {
        throw new UnsupportedOperationException("Should not be called!");
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void onComplete() {
        if (this.d) {
            return;
        }
        this.d = true;
        this.a.onComplete();
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void onError(Throwable th) {
        if (this.d) {
            C7.c(th);
        } else {
            this.d = true;
            this.a.onError(th);
        }
    }
}

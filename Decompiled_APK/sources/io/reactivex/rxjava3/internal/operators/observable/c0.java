package io.reactivex.rxjava3.internal.operators.observable;

import com.google.android.gms.internal.mlkit_vision_barcode.C7;
import com.google.android.gms.internal.mlkit_vision_barcode.x7;
import io.reactivex.rxjava3.exceptions.CompositeException;

/* loaded from: classes3.dex */
public final class c0 implements io.reactivex.rxjava3.core.l {
    public final io.reactivex.rxjava3.core.l a;
    public final io.reactivex.rxjava3.functions.h b;
    public final io.reactivex.rxjava3.disposables.d c = new io.reactivex.rxjava3.disposables.d(2);
    public boolean d;
    public boolean e;

    public c0(io.reactivex.rxjava3.core.l lVar, io.reactivex.rxjava3.functions.h hVar) {
        this.a = lVar;
        this.b = hVar;
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void a(io.reactivex.rxjava3.disposables.b bVar) {
        io.reactivex.rxjava3.disposables.d dVar = this.c;
        dVar.getClass();
        io.reactivex.rxjava3.internal.disposables.a.c(dVar, bVar);
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void b(Object obj) {
        if (this.e) {
            return;
        }
        this.a.b(obj);
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void onComplete() {
        if (this.e) {
            return;
        }
        this.e = true;
        this.d = true;
        this.a.onComplete();
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void onError(Throwable th) {
        boolean z = this.d;
        io.reactivex.rxjava3.core.l lVar = this.a;
        if (z) {
            if (this.e) {
                C7.c(th);
                return;
            } else {
                lVar.onError(th);
                return;
            }
        }
        this.d = true;
        try {
            io.reactivex.rxjava3.core.k kVar = (io.reactivex.rxjava3.core.k) this.b.apply(th);
            if (kVar != null) {
                kVar.c(this);
                return;
            }
            NullPointerException nullPointerException = new NullPointerException("Observable is null");
            nullPointerException.initCause(th);
            lVar.onError(nullPointerException);
        } catch (Throwable th2) {
            x7.b(th2);
            lVar.onError(new CompositeException(th, th2));
        }
    }
}

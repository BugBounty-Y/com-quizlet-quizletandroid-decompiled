package io.reactivex.rxjava3.core;

import com.google.android.gms.internal.mlkit_vision_barcode.C7;
import com.google.android.gms.internal.mlkit_vision_barcode.x7;
import java.util.Objects;

/* loaded from: classes3.dex */
public abstract class a implements d {
    public static a d(d... dVarArr) {
        if (dVarArr.length == 0) {
            return io.reactivex.rxjava3.internal.operators.completable.f.a;
        }
        if (dVarArr.length != 1) {
            return new io.reactivex.rxjava3.internal.operators.completable.c(dVarArr, 8);
        }
        d dVar = dVarArr[0];
        Objects.requireNonNull(dVar, "source is null");
        return dVar instanceof a ? (a) dVar : new io.reactivex.rxjava3.internal.operators.completable.c(dVar, 7);
    }

    @Override // io.reactivex.rxjava3.core.d
    public final void b(b bVar) {
        Objects.requireNonNull(bVar, "observer is null");
        try {
            g(bVar);
        } catch (NullPointerException e) {
            throw e;
        } catch (Throwable th) {
            x7.b(th);
            C7.c(th);
            NullPointerException nullPointerException = new NullPointerException("Actually not, but can't pass out an exception otherwise...");
            nullPointerException.initCause(th);
            throw nullPointerException;
        }
    }

    public final io.reactivex.rxjava3.disposables.b e() {
        io.reactivex.rxjava3.disposables.d dVar = new io.reactivex.rxjava3.disposables.d(3);
        b(dVar);
        return dVar;
    }

    public final io.reactivex.rxjava3.internal.observers.e f(io.reactivex.rxjava3.functions.a aVar, io.reactivex.rxjava3.functions.d dVar) {
        Objects.requireNonNull(aVar, "onComplete is null");
        io.reactivex.rxjava3.internal.observers.e eVar = new io.reactivex.rxjava3.internal.observers.e(0, dVar, aVar);
        b(eVar);
        return eVar;
    }

    public abstract void g(b bVar);

    public final io.reactivex.rxjava3.internal.operators.completable.h h(o oVar) {
        Objects.requireNonNull(oVar, "scheduler is null");
        return new io.reactivex.rxjava3.internal.operators.completable.h(this, oVar, 1);
    }
}

package io.reactivex.rxjava3.internal.operators.single;

import com.google.android.gms.internal.mlkit_vision_barcode.x7;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicReference;

/* loaded from: classes3.dex */
public final class q extends AtomicReference implements io.reactivex.rxjava3.core.q {
    public final p a;
    public final int b;

    public q(p pVar, int i) {
        this.a = pVar;
        this.b = i;
    }

    @Override // io.reactivex.rxjava3.core.q
    public final void a(io.reactivex.rxjava3.disposables.b bVar) {
        io.reactivex.rxjava3.internal.disposables.a.e(this, bVar);
    }

    @Override // io.reactivex.rxjava3.core.q
    public final void onError(Throwable th) {
        this.a.a(this.b, th);
    }

    @Override // io.reactivex.rxjava3.core.q, com.google.android.gms.tasks.d
    public final void onSuccess(Object obj) {
        p pVar = this.a;
        io.reactivex.rxjava3.core.q qVar = pVar.a;
        Object[] objArr = pVar.d;
        if (objArr != null) {
            objArr[this.b] = obj;
        }
        if (pVar.decrementAndGet() == 0) {
            try {
                Object objApply = pVar.b.apply(objArr);
                Objects.requireNonNull(objApply, "The zipper returned a null value");
                pVar.d = null;
                qVar.onSuccess(objApply);
            } catch (Throwable th) {
                x7.b(th);
                pVar.d = null;
                qVar.onError(th);
            }
        }
    }
}

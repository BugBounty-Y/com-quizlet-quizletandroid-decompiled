package io.reactivex.rxjava3.internal.operators.completable;

import com.google.android.gms.internal.mlkit_vision_barcode.x7;
import io.reactivex.rxjava3.exceptions.CompositeException;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicReference;

/* loaded from: classes3.dex */
public final class j extends AtomicReference implements io.reactivex.rxjava3.core.b, io.reactivex.rxjava3.disposables.b {
    public final io.reactivex.rxjava3.core.b a;
    public final io.reactivex.rxjava3.functions.h b;
    public boolean c;

    public j(io.reactivex.rxjava3.core.b bVar, io.reactivex.rxjava3.functions.h hVar) {
        this.a = bVar;
        this.b = hVar;
    }

    @Override // io.reactivex.rxjava3.core.b
    public final void a(io.reactivex.rxjava3.disposables.b bVar) {
        io.reactivex.rxjava3.internal.disposables.a.c(this, bVar);
    }

    @Override // io.reactivex.rxjava3.disposables.b
    public final void dispose() {
        io.reactivex.rxjava3.internal.disposables.a.a(this);
    }

    @Override // io.reactivex.rxjava3.core.b
    public final void onComplete() {
        this.a.onComplete();
    }

    @Override // io.reactivex.rxjava3.core.b
    public final void onError(Throwable th) {
        boolean z = this.c;
        io.reactivex.rxjava3.core.b bVar = this.a;
        if (z) {
            bVar.onError(th);
            return;
        }
        this.c = true;
        try {
            Object objApply = this.b.apply(th);
            Objects.requireNonNull(objApply, "The errorMapper returned a null CompletableSource");
            ((io.reactivex.rxjava3.core.d) objApply).b(this);
        } catch (Throwable th2) {
            x7.b(th2);
            bVar.onError(new CompositeException(th, th2));
        }
    }
}

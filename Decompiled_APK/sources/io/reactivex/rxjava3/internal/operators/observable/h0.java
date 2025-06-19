package io.reactivex.rxjava3.internal.operators.observable;

import com.google.android.gms.internal.mlkit_vision_barcode.C7;
import com.google.android.gms.internal.mlkit_vision_barcode.x7;
import java.util.Objects;

/* loaded from: classes3.dex */
public final class h0 implements io.reactivex.rxjava3.core.l, io.reactivex.rxjava3.disposables.b {
    public final io.reactivex.rxjava3.core.h a;
    public final io.reactivex.rxjava3.functions.b b;
    public boolean c;
    public Object d;
    public io.reactivex.rxjava3.disposables.b e;

    public h0(io.reactivex.rxjava3.core.h hVar, io.reactivex.rxjava3.functions.b bVar) {
        this.a = hVar;
        this.b = bVar;
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
        if (this.c) {
            return;
        }
        Object obj2 = this.d;
        if (obj2 == null) {
            this.d = obj;
            return;
        }
        try {
            Object objApply = this.b.apply(obj2, obj);
            Objects.requireNonNull(objApply, "The reducer returned a null value");
            this.d = objApply;
        } catch (Throwable th) {
            x7.b(th);
            this.e.dispose();
            onError(th);
        }
    }

    @Override // io.reactivex.rxjava3.disposables.b
    public final void dispose() {
        this.e.dispose();
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void onComplete() {
        if (this.c) {
            return;
        }
        this.c = true;
        Object obj = this.d;
        this.d = null;
        io.reactivex.rxjava3.core.h hVar = this.a;
        if (obj != null) {
            hVar.onSuccess(obj);
        } else {
            hVar.onComplete();
        }
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void onError(Throwable th) {
        if (this.c) {
            C7.c(th);
            return;
        }
        this.c = true;
        this.d = null;
        this.a.onError(th);
    }
}

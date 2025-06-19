package io.reactivex.rxjava3.internal.operators.observable;

import com.google.android.gms.internal.mlkit_vision_barcode.C7;
import com.google.android.gms.internal.mlkit_vision_barcode.x7;
import io.reactivex.rxjava3.exceptions.CompositeException;

/* loaded from: classes3.dex */
public final class A implements io.reactivex.rxjava3.core.l, io.reactivex.rxjava3.disposables.b {
    public final io.reactivex.rxjava3.core.l a;
    public final io.reactivex.rxjava3.functions.d b;
    public final io.reactivex.rxjava3.functions.d c;
    public final io.reactivex.rxjava3.functions.a d;
    public final io.reactivex.rxjava3.functions.a e;
    public io.reactivex.rxjava3.disposables.b f;
    public boolean g;

    public A(io.reactivex.rxjava3.core.l lVar, io.reactivex.rxjava3.functions.d dVar, io.reactivex.rxjava3.functions.d dVar2, io.reactivex.rxjava3.functions.a aVar, io.reactivex.rxjava3.functions.a aVar2) {
        this.a = lVar;
        this.b = dVar;
        this.c = dVar2;
        this.d = aVar;
        this.e = aVar2;
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
        if (this.g) {
            return;
        }
        try {
            this.b.accept(obj);
            this.a.b(obj);
        } catch (Throwable th) {
            x7.b(th);
            this.f.dispose();
            onError(th);
        }
    }

    @Override // io.reactivex.rxjava3.disposables.b
    public final void dispose() {
        this.f.dispose();
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void onComplete() {
        if (this.g) {
            return;
        }
        try {
            this.d.run();
            this.g = true;
            this.a.onComplete();
            try {
                this.e.run();
            } catch (Throwable th) {
                x7.b(th);
                C7.c(th);
            }
        } catch (Throwable th2) {
            x7.b(th2);
            onError(th2);
        }
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void onError(Throwable th) {
        if (this.g) {
            C7.c(th);
            return;
        }
        this.g = true;
        try {
            this.c.accept(th);
        } catch (Throwable th2) {
            x7.b(th2);
            th = new CompositeException(th, th2);
        }
        this.a.onError(th);
        try {
            this.e.run();
        } catch (Throwable th3) {
            x7.b(th3);
            C7.c(th3);
        }
    }
}

package io.reactivex.rxjava3.internal.operators.single;

import com.google.android.gms.internal.mlkit_vision_barcode.C7;
import com.google.android.gms.internal.mlkit_vision_barcode.x7;
import io.reactivex.rxjava3.exceptions.CompositeException;
import java.util.concurrent.atomic.AtomicReference;

/* loaded from: classes3.dex */
public final class o extends AtomicReference implements io.reactivex.rxjava3.core.q, io.reactivex.rxjava3.disposables.b {
    public final io.reactivex.rxjava3.core.q a;
    public final com.quizlet.billing.manager.b b;
    public final boolean c;
    public io.reactivex.rxjava3.disposables.b d;

    public o(io.reactivex.rxjava3.core.q qVar, Object obj, com.quizlet.billing.manager.b bVar) {
        super(obj);
        this.a = qVar;
        this.c = true;
        this.b = bVar;
    }

    @Override // io.reactivex.rxjava3.core.q
    public final void a(io.reactivex.rxjava3.disposables.b bVar) {
        if (io.reactivex.rxjava3.internal.disposables.a.f(this.d, bVar)) {
            this.d = bVar;
            this.a.a(this);
        }
    }

    public final void b() {
        Object andSet = getAndSet(this);
        if (andSet != this) {
            try {
                this.b.accept(andSet);
            } catch (Throwable th) {
                x7.b(th);
                C7.c(th);
            }
        }
    }

    @Override // io.reactivex.rxjava3.disposables.b
    public final void dispose() {
        io.reactivex.rxjava3.internal.disposables.a aVar = io.reactivex.rxjava3.internal.disposables.a.a;
        if (this.c) {
            b();
            this.d.dispose();
            this.d = aVar;
        } else {
            this.d.dispose();
            this.d = aVar;
            b();
        }
    }

    @Override // io.reactivex.rxjava3.core.q
    public final void onError(Throwable th) {
        this.d = io.reactivex.rxjava3.internal.disposables.a.a;
        boolean z = this.c;
        if (z) {
            Object andSet = getAndSet(this);
            if (andSet == this) {
                return;
            }
            try {
                this.b.accept(andSet);
            } catch (Throwable th2) {
                x7.b(th2);
                th = new CompositeException(th, th2);
            }
        }
        this.a.onError(th);
        if (z) {
            return;
        }
        b();
    }

    @Override // io.reactivex.rxjava3.core.q, com.google.android.gms.tasks.d
    public final void onSuccess(Object obj) {
        this.d = io.reactivex.rxjava3.internal.disposables.a.a;
        io.reactivex.rxjava3.core.q qVar = this.a;
        boolean z = this.c;
        if (z) {
            Object andSet = getAndSet(this);
            if (andSet == this) {
                return;
            }
            try {
                this.b.accept(andSet);
            } catch (Throwable th) {
                x7.b(th);
                qVar.onError(th);
                return;
            }
        }
        qVar.onSuccess(obj);
        if (z) {
            return;
        }
        b();
    }
}

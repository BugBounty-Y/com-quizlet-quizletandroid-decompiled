package io.reactivex.rxjava3.internal.observers;

import com.google.android.gms.internal.mlkit_vision_barcode.C7;
import com.google.android.gms.internal.mlkit_vision_barcode.x7;
import io.reactivex.rxjava3.core.l;
import io.reactivex.rxjava3.exceptions.CompositeException;
import java.util.concurrent.atomic.AtomicReference;

/* loaded from: classes3.dex */
public final class h extends AtomicReference implements l, io.reactivex.rxjava3.disposables.b {
    public final io.reactivex.rxjava3.functions.d a;
    public final io.reactivex.rxjava3.functions.d b;
    public final io.reactivex.rxjava3.functions.a c;
    public final com.quizlet.infra.legacysyncengine.net.request.g d;

    public h(io.reactivex.rxjava3.functions.d dVar, io.reactivex.rxjava3.functions.d dVar2, io.reactivex.rxjava3.functions.a aVar) {
        com.quizlet.infra.legacysyncengine.net.request.g gVar = io.reactivex.rxjava3.internal.functions.d.d;
        this.a = dVar;
        this.b = dVar2;
        this.c = aVar;
        this.d = gVar;
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void a(io.reactivex.rxjava3.disposables.b bVar) {
        if (io.reactivex.rxjava3.internal.disposables.a.e(this, bVar)) {
            try {
                this.d.getClass();
            } catch (Throwable th) {
                x7.b(th);
                bVar.dispose();
                onError(th);
            }
        }
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void b(Object obj) {
        if (c()) {
            return;
        }
        try {
            this.a.accept(obj);
        } catch (Throwable th) {
            x7.b(th);
            ((io.reactivex.rxjava3.disposables.b) get()).dispose();
            onError(th);
        }
    }

    public final boolean c() {
        return get() == io.reactivex.rxjava3.internal.disposables.a.a;
    }

    @Override // io.reactivex.rxjava3.disposables.b
    public final void dispose() {
        io.reactivex.rxjava3.internal.disposables.a.a(this);
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void onComplete() {
        if (c()) {
            return;
        }
        lazySet(io.reactivex.rxjava3.internal.disposables.a.a);
        try {
            this.c.run();
        } catch (Throwable th) {
            x7.b(th);
            C7.c(th);
        }
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void onError(Throwable th) {
        if (c()) {
            C7.c(th);
            return;
        }
        lazySet(io.reactivex.rxjava3.internal.disposables.a.a);
        try {
            this.b.accept(th);
        } catch (Throwable th2) {
            x7.b(th2);
            C7.c(new CompositeException(th, th2));
        }
    }
}

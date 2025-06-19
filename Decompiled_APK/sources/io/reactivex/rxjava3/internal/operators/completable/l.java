package io.reactivex.rxjava3.internal.operators.completable;

import com.google.android.gms.internal.mlkit_vision_barcode.C7;
import com.google.android.gms.internal.mlkit_vision_barcode.x7;
import com.quizlet.quizletandroid.ui.setcreation.managers.n;
import io.reactivex.rxjava3.exceptions.CompositeException;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

/* loaded from: classes3.dex */
public final class l extends AtomicReference implements io.reactivex.rxjava3.core.b, io.reactivex.rxjava3.disposables.b, io.reactivex.rxjava3.core.h {
    public final /* synthetic */ int a;
    public final Object b;
    public final Object c;
    public Object d;

    public l(io.reactivex.rxjava3.functions.d dVar, io.reactivex.rxjava3.functions.d dVar2, io.reactivex.rxjava3.functions.a aVar) {
        this.a = 1;
        this.b = dVar;
        this.c = dVar2;
        this.d = aVar;
    }

    @Override // io.reactivex.rxjava3.core.b
    public final void a(io.reactivex.rxjava3.disposables.b bVar) {
        switch (this.a) {
            case 0:
                io.reactivex.rxjava3.internal.disposables.a.e(this, bVar);
                break;
            case 1:
                io.reactivex.rxjava3.internal.disposables.a.e(this, bVar);
                break;
            default:
                if (io.reactivex.rxjava3.internal.disposables.a.f((io.reactivex.rxjava3.disposables.b) this.d, bVar)) {
                    this.d = bVar;
                    ((io.reactivex.rxjava3.core.h) this.b).a(this);
                    break;
                }
                break;
        }
    }

    @Override // io.reactivex.rxjava3.disposables.b
    public final void dispose() {
        switch (this.a) {
            case 0:
                if (((AtomicBoolean) this.d).compareAndSet(false, true)) {
                    io.reactivex.rxjava3.internal.disposables.a.a(this);
                    io.reactivex.rxjava3.internal.disposables.a.a((k) this.c);
                    break;
                }
                break;
            case 1:
                io.reactivex.rxjava3.internal.disposables.a.a(this);
                break;
            default:
                io.reactivex.rxjava3.internal.disposables.a.a(this);
                ((io.reactivex.rxjava3.disposables.b) this.d).dispose();
                break;
        }
    }

    @Override // io.reactivex.rxjava3.core.b
    public final void onComplete() {
        switch (this.a) {
            case 0:
                if (((AtomicBoolean) this.d).compareAndSet(false, true)) {
                    io.reactivex.rxjava3.internal.disposables.a.a((k) this.c);
                    ((io.reactivex.rxjava3.core.b) this.b).onComplete();
                    break;
                }
                break;
            case 1:
                lazySet(io.reactivex.rxjava3.internal.disposables.a.a);
                try {
                    ((io.reactivex.rxjava3.functions.a) this.d).run();
                    break;
                } catch (Throwable th) {
                    x7.b(th);
                    C7.c(th);
                    return;
                }
            default:
                ((io.reactivex.rxjava3.core.h) this.b).onComplete();
                break;
        }
    }

    @Override // io.reactivex.rxjava3.core.b
    public final void onError(Throwable th) {
        switch (this.a) {
            case 0:
                if (!((AtomicBoolean) this.d).compareAndSet(false, true)) {
                    C7.c(th);
                    break;
                } else {
                    io.reactivex.rxjava3.internal.disposables.a.a((k) this.c);
                    ((io.reactivex.rxjava3.core.b) this.b).onError(th);
                    break;
                }
            case 1:
                lazySet(io.reactivex.rxjava3.internal.disposables.a.a);
                try {
                    ((io.reactivex.rxjava3.functions.d) this.c).accept(th);
                    break;
                } catch (Throwable th2) {
                    x7.b(th2);
                    C7.c(new CompositeException(th, th2));
                    return;
                }
            default:
                ((io.reactivex.rxjava3.core.h) this.b).onError(th);
                break;
        }
    }

    @Override // io.reactivex.rxjava3.core.h, io.reactivex.rxjava3.core.q, com.google.android.gms.tasks.d
    public void onSuccess(Object obj) {
        switch (this.a) {
            case 1:
                lazySet(io.reactivex.rxjava3.internal.disposables.a.a);
                try {
                    ((io.reactivex.rxjava3.functions.d) this.b).accept(obj);
                    break;
                } catch (Throwable th) {
                    x7.b(th);
                    C7.c(th);
                }
            default:
                try {
                    Object objApply = ((io.reactivex.rxjava3.functions.h) this.c).apply(obj);
                    Objects.requireNonNull(objApply, "The mapper returned a null MaybeSource");
                    io.reactivex.rxjava3.core.g gVar = (io.reactivex.rxjava3.core.g) objApply;
                    if (!io.reactivex.rxjava3.internal.disposables.a.b((io.reactivex.rxjava3.disposables.b) get())) {
                        gVar.e(new n(this, 11));
                        break;
                    }
                } catch (Throwable th2) {
                    x7.b(th2);
                    ((io.reactivex.rxjava3.core.h) this.b).onError(th2);
                    return;
                }
                break;
        }
    }

    public l(io.reactivex.rxjava3.core.h hVar, io.reactivex.rxjava3.functions.h hVar2) {
        this.a = 2;
        this.b = hVar;
        this.c = hVar2;
    }

    public l(io.reactivex.rxjava3.core.b bVar) {
        this.a = 0;
        this.b = bVar;
        this.c = new k(this, 0);
        this.d = new AtomicBoolean();
    }
}

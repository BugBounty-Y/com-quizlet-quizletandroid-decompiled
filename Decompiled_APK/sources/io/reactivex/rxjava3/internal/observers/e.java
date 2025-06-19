package io.reactivex.rxjava3.internal.observers;

import com.google.android.gms.internal.mlkit_vision_barcode.C7;
import com.google.android.gms.internal.mlkit_vision_barcode.x7;
import io.reactivex.rxjava3.core.p;
import io.reactivex.rxjava3.core.q;
import io.reactivex.rxjava3.exceptions.CompositeException;
import io.reactivex.rxjava3.internal.operators.completable.k;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicReference;

/* loaded from: classes3.dex */
public final class e extends AtomicReference implements io.reactivex.rxjava3.core.b, io.reactivex.rxjava3.disposables.b, q, io.reactivex.rxjava3.core.h {
    public final /* synthetic */ int a;
    public final Object b;
    public Object c;

    public /* synthetic */ e(int i, Object obj, Object obj2) {
        this.a = i;
        this.b = obj;
        this.c = obj2;
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
            case 2:
                if (io.reactivex.rxjava3.internal.disposables.a.e(this, bVar)) {
                    ((io.reactivex.rxjava3.core.b) this.b).a(this);
                    break;
                }
                break;
            case 3:
                io.reactivex.rxjava3.internal.disposables.a.c(this, bVar);
                break;
            case 4:
                if (io.reactivex.rxjava3.internal.disposables.a.e(this, bVar)) {
                    ((io.reactivex.rxjava3.core.h) this.b).a(this);
                    break;
                }
                break;
            case 5:
                io.reactivex.rxjava3.internal.disposables.a.e(this, bVar);
                break;
            case 6:
                if (io.reactivex.rxjava3.internal.disposables.a.e(this, bVar)) {
                    ((q) this.b).a(this);
                    break;
                }
                break;
            case 7:
                if (io.reactivex.rxjava3.internal.disposables.a.f((io.reactivex.rxjava3.disposables.b) this.c, bVar)) {
                    this.c = bVar;
                    ((q) this.b).a(this);
                    break;
                }
                break;
            case 8:
                io.reactivex.rxjava3.internal.disposables.a.c(this, bVar);
                break;
            default:
                io.reactivex.rxjava3.internal.disposables.a.e(this, bVar);
                break;
        }
    }

    public boolean b() {
        switch (this.a) {
            case 0:
                if (get() == io.reactivex.rxjava3.internal.disposables.a.a) {
                }
                break;
            case 1:
                if (get() == io.reactivex.rxjava3.internal.disposables.a.a) {
                }
                break;
        }
        return io.reactivex.rxjava3.internal.disposables.a.b((io.reactivex.rxjava3.disposables.b) get());
    }

    public void c(Throwable th) {
        io.reactivex.rxjava3.disposables.b bVar;
        io.reactivex.rxjava3.disposables.b bVar2 = (io.reactivex.rxjava3.disposables.b) get();
        io.reactivex.rxjava3.internal.disposables.a aVar = io.reactivex.rxjava3.internal.disposables.a.a;
        if (bVar2 == aVar || (bVar = (io.reactivex.rxjava3.disposables.b) getAndSet(aVar)) == aVar) {
            C7.c(th);
            return;
        }
        if (bVar != null) {
            bVar.dispose();
        }
        ((q) this.b).onError(th);
    }

    @Override // io.reactivex.rxjava3.disposables.b
    public final void dispose() {
        switch (this.a) {
            case 0:
                io.reactivex.rxjava3.internal.disposables.a.a(this);
                break;
            case 1:
                io.reactivex.rxjava3.internal.disposables.a.a(this);
                break;
            case 2:
                io.reactivex.rxjava3.internal.disposables.a.a(this);
                break;
            case 3:
                io.reactivex.rxjava3.internal.disposables.a.a(this);
                break;
            case 4:
                io.reactivex.rxjava3.internal.disposables.a.a(this);
                break;
            case 5:
                io.reactivex.rxjava3.internal.disposables.a.a(this);
                io.reactivex.rxjava3.disposables.d dVar = (io.reactivex.rxjava3.disposables.d) this.b;
                dVar.getClass();
                io.reactivex.rxjava3.internal.disposables.a.a(dVar);
                break;
            case 6:
                io.reactivex.rxjava3.internal.disposables.a.a(this);
                break;
            case 7:
                io.reactivex.rxjava3.functions.a aVar = (io.reactivex.rxjava3.functions.a) getAndSet(null);
                if (aVar != null) {
                    try {
                        aVar.run();
                    } catch (Throwable th) {
                        x7.b(th);
                        C7.c(th);
                    }
                    ((io.reactivex.rxjava3.disposables.b) this.c).dispose();
                    break;
                }
                break;
            case 8:
                io.reactivex.rxjava3.internal.disposables.a.a(this);
                break;
            default:
                io.reactivex.rxjava3.internal.disposables.a.a(this);
                k kVar = (k) this.c;
                kVar.getClass();
                io.reactivex.rxjava3.internal.subscriptions.c.a(kVar);
                break;
        }
    }

    @Override // io.reactivex.rxjava3.core.b
    public void onComplete() {
        switch (this.a) {
            case 0:
                try {
                    ((io.reactivex.rxjava3.functions.a) this.c).run();
                } catch (Throwable th) {
                    x7.b(th);
                    C7.c(th);
                }
                lazySet(io.reactivex.rxjava3.internal.disposables.a.a);
                break;
            case 1:
            default:
                ((io.reactivex.rxjava3.core.b) this.b).onComplete();
                break;
            case 2:
                ((io.reactivex.rxjava3.core.d) this.c).b(new com.quizlet.remote.model.report.c(this, (io.reactivex.rxjava3.core.b) this.b));
                break;
            case 3:
                ((io.reactivex.rxjava3.core.b) this.b).onComplete();
                break;
            case 4:
                ((io.reactivex.rxjava3.core.h) this.b).onComplete();
                break;
            case 5:
                ((io.reactivex.rxjava3.core.h) this.c).onComplete();
                break;
            case 6:
                ((p) this.c).j(new com.quizlet.remote.model.progress.e(this, (q) this.b));
                break;
        }
    }

    @Override // io.reactivex.rxjava3.core.b
    public final void onError(Throwable th) {
        switch (this.a) {
            case 0:
                try {
                    ((io.reactivex.rxjava3.functions.d) this.b).accept(th);
                } catch (Throwable th2) {
                    x7.b(th2);
                    C7.c(th2);
                }
                lazySet(io.reactivex.rxjava3.internal.disposables.a.a);
                break;
            case 1:
                lazySet(io.reactivex.rxjava3.internal.disposables.a.a);
                try {
                    ((io.reactivex.rxjava3.functions.d) this.c).accept(th);
                    break;
                } catch (Throwable th3) {
                    x7.b(th3);
                    C7.c(new CompositeException(th, th3));
                    return;
                }
            case 2:
                ((io.reactivex.rxjava3.core.b) this.b).onError(th);
                break;
            case 3:
                ((io.reactivex.rxjava3.core.b) this.b).onError(th);
                break;
            case 4:
                io.reactivex.rxjava3.core.h hVar = (io.reactivex.rxjava3.core.h) this.b;
                try {
                    io.reactivex.rxjava3.core.g gVar = (io.reactivex.rxjava3.core.g) ((com.quizlet.remote.model.progress.e) this.c).apply(th);
                    io.reactivex.rxjava3.internal.disposables.a.c(this, null);
                    gVar.e(new com.quizlet.remote.model.set.d(hVar, this));
                    break;
                } catch (Throwable th4) {
                    x7.b(th4);
                    hVar.onError(new CompositeException(th, th4));
                    return;
                }
            case 5:
                ((io.reactivex.rxjava3.core.h) this.c).onError(th);
                break;
            case 6:
                ((q) this.b).onError(th);
                break;
            case 7:
                ((q) this.b).onError(th);
                break;
            case 8:
                ((io.reactivex.rxjava3.core.b) this.b).onError(th);
                break;
            default:
                k kVar = (k) this.c;
                kVar.getClass();
                io.reactivex.rxjava3.internal.subscriptions.c.a(kVar);
                io.reactivex.rxjava3.disposables.b bVar = (io.reactivex.rxjava3.disposables.b) get();
                io.reactivex.rxjava3.internal.disposables.a aVar = io.reactivex.rxjava3.internal.disposables.a.a;
                if (bVar != aVar && ((io.reactivex.rxjava3.disposables.b) getAndSet(aVar)) != aVar) {
                    ((q) this.b).onError(th);
                    break;
                } else {
                    C7.c(th);
                    break;
                }
                break;
        }
    }

    @Override // io.reactivex.rxjava3.core.q, com.google.android.gms.tasks.d
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
                    return;
                }
            case 2:
            case 6:
            default:
                k kVar = (k) this.c;
                kVar.getClass();
                io.reactivex.rxjava3.internal.subscriptions.c.a(kVar);
                io.reactivex.rxjava3.internal.disposables.a aVar = io.reactivex.rxjava3.internal.disposables.a.a;
                if (((io.reactivex.rxjava3.disposables.b) getAndSet(aVar)) != aVar) {
                    ((q) this.b).onSuccess(obj);
                    break;
                }
                break;
            case 3:
                try {
                    io.reactivex.rxjava3.core.d dVar = (io.reactivex.rxjava3.core.d) ((com.quizlet.login.authentication.login.a) this.c).apply(obj);
                    if (!b()) {
                        dVar.b(this);
                        break;
                    }
                } catch (Throwable th2) {
                    x7.b(th2);
                    onError(th2);
                    return;
                }
                break;
            case 4:
                ((io.reactivex.rxjava3.core.h) this.b).onSuccess(obj);
                break;
            case 5:
                ((io.reactivex.rxjava3.core.h) this.c).onSuccess(obj);
                break;
            case 7:
                ((q) this.b).onSuccess(obj);
                break;
            case 8:
                try {
                    Object objApply = ((io.reactivex.rxjava3.functions.h) this.c).apply(obj);
                    Objects.requireNonNull(objApply, "The mapper returned a null CompletableSource");
                    io.reactivex.rxjava3.core.d dVar2 = (io.reactivex.rxjava3.core.d) objApply;
                    if (!b()) {
                        dVar2.b(this);
                        break;
                    }
                } catch (Throwable th3) {
                    x7.b(th3);
                    onError(th3);
                    return;
                }
                break;
        }
    }

    public e(q qVar, com.quizlet.eventlogger.e eVar) {
        this.a = 7;
        this.b = qVar;
        lazySet(eVar);
    }

    public e(q qVar) {
        this.a = 9;
        this.b = qVar;
        this.c = new k(this, 1);
    }

    public e(io.reactivex.rxjava3.core.h hVar) {
        this.a = 5;
        this.c = hVar;
        this.b = new io.reactivex.rxjava3.disposables.d(2);
    }
}

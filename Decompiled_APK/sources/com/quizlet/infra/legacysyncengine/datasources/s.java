package com.quizlet.infra.legacysyncengine.datasources;

import com.google.android.gms.internal.mlkit_vision_barcode.C7;
import com.google.android.gms.internal.mlkit_vision_barcode.x7;
import io.reactivex.rxjava3.exceptions.CompositeException;
import java.util.NoSuchElementException;
import java.util.Objects;

/* loaded from: classes3.dex */
public final class s implements io.reactivex.rxjava3.disposables.b, io.reactivex.rxjava3.core.b, io.reactivex.rxjava3.core.h, io.reactivex.rxjava3.core.q {
    public final /* synthetic */ int a;
    public Object b;
    public final Object c;
    public Object d;

    public /* synthetic */ s(int i, Object obj, Object obj2) {
        this.a = i;
        this.c = obj;
        this.b = obj2;
    }

    @Override // io.reactivex.rxjava3.core.b
    public void a(io.reactivex.rxjava3.disposables.b bVar) {
        switch (this.a) {
            case 3:
                io.reactivex.rxjava3.core.b bVar2 = (io.reactivex.rxjava3.core.b) this.c;
                try {
                    ((io.reactivex.rxjava3.internal.operators.completable.i) this.d).b.accept(bVar);
                    if (io.reactivex.rxjava3.internal.disposables.a.f((io.reactivex.rxjava3.disposables.b) this.b, bVar)) {
                        this.b = bVar;
                        bVar2.a(this);
                        break;
                    }
                } catch (Throwable th) {
                    x7.b(th);
                    bVar.dispose();
                    this.b = io.reactivex.rxjava3.internal.disposables.a.a;
                    io.reactivex.rxjava3.internal.disposables.b.b(th, bVar2);
                    return;
                }
                break;
            case 4:
                if (io.reactivex.rxjava3.internal.disposables.a.f((io.reactivex.rxjava3.disposables.b) this.d, bVar)) {
                    this.d = bVar;
                    ((io.reactivex.rxjava3.core.h) this.c).a(this);
                    break;
                }
                break;
            case 5:
                if (io.reactivex.rxjava3.internal.disposables.a.f((io.reactivex.rxjava3.disposables.b) this.d, bVar)) {
                    this.d = bVar;
                    ((io.reactivex.rxjava3.core.h) this.c).a(this);
                    break;
                }
                break;
            case 6:
                io.reactivex.rxjava3.core.h hVar = (io.reactivex.rxjava3.core.h) this.c;
                if (io.reactivex.rxjava3.internal.disposables.a.f((io.reactivex.rxjava3.disposables.b) this.d, bVar)) {
                    try {
                        ((io.reactivex.rxjava3.internal.operators.maybe.u) this.b).b.accept(bVar);
                        this.d = bVar;
                        hVar.a(this);
                        break;
                    } catch (Throwable th2) {
                        x7.b(th2);
                        bVar.dispose();
                        this.d = io.reactivex.rxjava3.internal.disposables.a.a;
                        hVar.a(io.reactivex.rxjava3.internal.disposables.b.a);
                        hVar.onError(th2);
                        return;
                    }
                }
                break;
            case 7:
                if (io.reactivex.rxjava3.internal.disposables.a.f((io.reactivex.rxjava3.disposables.b) this.d, bVar)) {
                    this.d = bVar;
                    ((io.reactivex.rxjava3.core.q) this.c).a(this);
                    break;
                }
                break;
            case 8:
                if (io.reactivex.rxjava3.internal.disposables.a.f((io.reactivex.rxjava3.disposables.b) this.d, bVar)) {
                    this.d = bVar;
                    ((io.reactivex.rxjava3.core.q) this.c).a(this);
                    break;
                }
                break;
            default:
                if (io.reactivex.rxjava3.internal.disposables.a.f((io.reactivex.rxjava3.disposables.b) this.d, bVar)) {
                    this.d = bVar;
                    ((io.reactivex.rxjava3.core.q) this.c).a(this);
                    break;
                }
                break;
        }
    }

    public void b() {
        try {
            ((io.reactivex.rxjava3.internal.operators.maybe.u) this.b).getClass();
        } catch (Throwable th) {
            x7.b(th);
            C7.c(th);
        }
    }

    public void c(Throwable th) {
        try {
            ((io.reactivex.rxjava3.internal.operators.maybe.u) this.b).d.accept(th);
        } catch (Throwable th2) {
            x7.b(th2);
            th = new CompositeException(th, th2);
        }
        this.d = io.reactivex.rxjava3.internal.disposables.a.a;
        ((io.reactivex.rxjava3.core.h) this.c).onError(th);
        b();
    }

    @Override // io.reactivex.rxjava3.disposables.b
    public final void dispose() {
        switch (this.a) {
            case 0:
                ((p) this.c).c.a((com.quizlet.infra.legacysyncengine.orm.query.a) this.b, (q) this.d);
                break;
            case 1:
                ((p) this.c).c.a((com.quizlet.infra.legacysyncengine.orm.query.a) this.b, (q) this.d);
                break;
            case 2:
                ((w) this.d).b.a((com.quizlet.infra.legacysyncengine.orm.query.a) this.b, (q) this.c);
                break;
            case 3:
                try {
                    ((io.reactivex.rxjava3.internal.operators.completable.i) this.d).e.run();
                } catch (Throwable th) {
                    x7.b(th);
                    C7.c(th);
                }
                ((io.reactivex.rxjava3.disposables.b) this.b).dispose();
                break;
            case 4:
                io.reactivex.rxjava3.disposables.b bVar = (io.reactivex.rxjava3.disposables.b) this.d;
                this.d = io.reactivex.rxjava3.internal.disposables.a.a;
                bVar.dispose();
                break;
            case 5:
                io.reactivex.rxjava3.disposables.b bVar2 = (io.reactivex.rxjava3.disposables.b) this.d;
                this.d = io.reactivex.rxjava3.internal.disposables.a.a;
                bVar2.dispose();
                break;
            case 6:
                try {
                    ((io.reactivex.rxjava3.internal.operators.maybe.u) this.b).getClass();
                } catch (Throwable th2) {
                    x7.b(th2);
                    C7.c(th2);
                }
                ((io.reactivex.rxjava3.disposables.b) this.d).dispose();
                this.d = io.reactivex.rxjava3.internal.disposables.a.a;
                break;
            case 7:
                ((io.reactivex.rxjava3.disposables.b) this.d).dispose();
                this.d = io.reactivex.rxjava3.internal.disposables.a.a;
                break;
            case 8:
                ((io.reactivex.rxjava3.disposables.b) this.d).dispose();
                break;
            default:
                ((io.reactivex.rxjava3.disposables.b) this.d).dispose();
                break;
        }
    }

    @Override // io.reactivex.rxjava3.core.b
    public void onComplete() {
        switch (this.a) {
            case 3:
                io.reactivex.rxjava3.core.b bVar = (io.reactivex.rxjava3.core.b) this.c;
                io.reactivex.rxjava3.internal.operators.completable.i iVar = (io.reactivex.rxjava3.internal.operators.completable.i) this.d;
                if (((io.reactivex.rxjava3.disposables.b) this.b) != io.reactivex.rxjava3.internal.disposables.a.a) {
                    try {
                        iVar.d.run();
                        bVar.onComplete();
                        try {
                            iVar.getClass();
                            break;
                        } catch (Throwable th) {
                            x7.b(th);
                            C7.c(th);
                            return;
                        }
                    } catch (Throwable th2) {
                        x7.b(th2);
                        bVar.onError(th2);
                        return;
                    }
                }
                break;
            case 4:
                ((io.reactivex.rxjava3.core.h) this.c).onComplete();
                break;
            case 5:
                ((io.reactivex.rxjava3.core.h) this.c).onComplete();
                break;
            case 6:
                io.reactivex.rxjava3.disposables.b bVar2 = (io.reactivex.rxjava3.disposables.b) this.d;
                io.reactivex.rxjava3.internal.disposables.a aVar = io.reactivex.rxjava3.internal.disposables.a.a;
                if (bVar2 != aVar) {
                    try {
                        ((io.reactivex.rxjava3.internal.operators.maybe.u) this.b).e.run();
                        this.d = aVar;
                        ((io.reactivex.rxjava3.core.h) this.c).onComplete();
                        b();
                        break;
                    } catch (Throwable th3) {
                        x7.b(th3);
                        c(th3);
                        return;
                    }
                }
                break;
            default:
                this.d = io.reactivex.rxjava3.internal.disposables.a.a;
                io.reactivex.rxjava3.core.q qVar = (io.reactivex.rxjava3.core.q) this.c;
                Object obj = this.b;
                if (obj == null) {
                    qVar.onError(new NoSuchElementException("The MaybeSource is empty"));
                    break;
                } else {
                    qVar.onSuccess(obj);
                    break;
                }
        }
    }

    @Override // io.reactivex.rxjava3.core.b
    public void onError(Throwable th) {
        switch (this.a) {
            case 3:
                io.reactivex.rxjava3.internal.operators.completable.i iVar = (io.reactivex.rxjava3.internal.operators.completable.i) this.d;
                if (((io.reactivex.rxjava3.disposables.b) this.b) == io.reactivex.rxjava3.internal.disposables.a.a) {
                    C7.c(th);
                    break;
                } else {
                    try {
                        iVar.c.accept(th);
                    } catch (Throwable th2) {
                        x7.b(th2);
                        th = new CompositeException(th, th2);
                    }
                    ((io.reactivex.rxjava3.core.b) this.c).onError(th);
                    try {
                        iVar.getClass();
                        break;
                    } catch (Throwable th3) {
                        x7.b(th3);
                        C7.c(th3);
                        return;
                    }
                }
            case 4:
                ((io.reactivex.rxjava3.core.h) this.c).onError(th);
                break;
            case 5:
                ((io.reactivex.rxjava3.core.h) this.c).onError(th);
                break;
            case 6:
                if (((io.reactivex.rxjava3.disposables.b) this.d) != io.reactivex.rxjava3.internal.disposables.a.a) {
                    c(th);
                    break;
                } else {
                    C7.c(th);
                    break;
                }
            case 7:
                this.d = io.reactivex.rxjava3.internal.disposables.a.a;
                ((io.reactivex.rxjava3.core.q) this.c).onError(th);
                break;
            case 8:
                ((io.reactivex.rxjava3.core.q) this.c).onError(th);
                break;
            default:
                ((io.reactivex.rxjava3.core.q) this.c).onError(th);
                try {
                    ((io.reactivex.rxjava3.functions.a) this.b).run();
                    break;
                } catch (Throwable th4) {
                    x7.b(th4);
                    C7.c(th4);
                }
        }
    }

    @Override // io.reactivex.rxjava3.core.h, io.reactivex.rxjava3.core.q, com.google.android.gms.tasks.d
    public void onSuccess(Object obj) {
        switch (this.a) {
            case 4:
                io.reactivex.rxjava3.core.h hVar = (io.reactivex.rxjava3.core.h) this.c;
                try {
                    if (!((com.quizlet.features.infra.basestudy.data.models.dataproviders.b) this.b).test(obj)) {
                        hVar.onComplete();
                        break;
                    } else {
                        hVar.onSuccess(obj);
                        break;
                    }
                } catch (Throwable th) {
                    x7.b(th);
                    hVar.onError(th);
                    return;
                }
            case 5:
                io.reactivex.rxjava3.core.h hVar2 = (io.reactivex.rxjava3.core.h) this.c;
                try {
                    Object objApply = ((io.reactivex.rxjava3.functions.h) this.b).apply(obj);
                    Objects.requireNonNull(objApply, "The mapper returned a null item");
                    hVar2.onSuccess(objApply);
                    break;
                } catch (Throwable th2) {
                    x7.b(th2);
                    hVar2.onError(th2);
                    return;
                }
            case 6:
                io.reactivex.rxjava3.disposables.b bVar = (io.reactivex.rxjava3.disposables.b) this.d;
                io.reactivex.rxjava3.internal.disposables.a aVar = io.reactivex.rxjava3.internal.disposables.a.a;
                if (bVar != aVar) {
                    try {
                        ((io.reactivex.rxjava3.internal.operators.maybe.u) this.b).c.accept(obj);
                        this.d = aVar;
                        ((io.reactivex.rxjava3.core.h) this.c).onSuccess(obj);
                        b();
                        break;
                    } catch (Throwable th3) {
                        x7.b(th3);
                        c(th3);
                        return;
                    }
                }
                break;
            case 7:
                this.d = io.reactivex.rxjava3.internal.disposables.a.a;
                ((io.reactivex.rxjava3.core.q) this.c).onSuccess(obj);
                break;
            case 8:
                ((io.reactivex.rxjava3.core.q) this.c).onSuccess(obj);
                try {
                    ((io.reactivex.rxjava3.functions.d) this.b).accept(obj);
                    break;
                } catch (Throwable th4) {
                    x7.b(th4);
                    C7.c(th4);
                    return;
                }
            default:
                ((io.reactivex.rxjava3.core.q) this.c).onSuccess(obj);
                try {
                    ((io.reactivex.rxjava3.functions.a) this.b).run();
                    break;
                } catch (Throwable th5) {
                    x7.b(th5);
                    C7.c(th5);
                }
        }
    }

    public /* synthetic */ s(c cVar, com.quizlet.infra.legacysyncengine.orm.query.a aVar, com.quizlet.infra.legacysyncengine.a aVar2, int i) {
        this.a = i;
        this.c = cVar;
        this.b = aVar;
        this.d = aVar2;
    }

    public s(io.reactivex.rxjava3.internal.operators.completable.i iVar, io.reactivex.rxjava3.core.b bVar) {
        this.a = 3;
        this.d = iVar;
        this.c = bVar;
    }

    public s(w wVar, com.quizlet.infra.legacysyncengine.orm.query.a aVar, q qVar) {
        this.a = 2;
        this.d = wVar;
        this.b = aVar;
        this.c = qVar;
    }
}

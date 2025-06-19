package io.reactivex.rxjava3.core;

import com.google.android.gms.internal.mlkit_vision_barcode.x7;
import io.reactivex.rxjava3.internal.operators.maybe.w;
import java.util.NoSuchElementException;
import java.util.Objects;

/* loaded from: classes3.dex */
public abstract class p<T> {
    public static io.reactivex.rxjava3.internal.operators.flowable.b d(Throwable th) {
        Objects.requireNonNull(th, "throwable is null");
        return new io.reactivex.rxjava3.internal.operators.flowable.b(new io.reactivex.rxjava3.internal.functions.c(th), 5);
    }

    public static io.reactivex.rxjava3.internal.operators.flowable.b f(Object obj) {
        Objects.requireNonNull(obj, "item is null");
        return new io.reactivex.rxjava3.internal.operators.flowable.b(obj, 7);
    }

    public static p n(p pVar, p pVar2, p pVar3, p pVar4, io.reactivex.rxjava3.functions.f fVar) {
        Objects.requireNonNull(pVar, "source1 is null");
        Objects.requireNonNull(pVar2, "source2 is null");
        Objects.requireNonNull(pVar3, "source3 is null");
        return q(new com.quizlet.quizletandroid.ui.activitycenter.views.i(fVar, 12), pVar, pVar2, pVar3, pVar4);
    }

    public static p o(p pVar, p pVar2, p pVar3, io.reactivex.rxjava3.functions.e eVar) {
        Objects.requireNonNull(pVar, "source1 is null");
        Objects.requireNonNull(pVar2, "source2 is null");
        Objects.requireNonNull(pVar3, "source3 is null");
        return q(new com.quizlet.quizletandroid.k(eVar, 18), pVar, pVar2, pVar3);
    }

    public static p p(p pVar, p pVar2, io.reactivex.rxjava3.functions.b bVar) {
        Objects.requireNonNull(pVar, "source1 is null");
        Objects.requireNonNull(pVar2, "source2 is null");
        return q(new com.quizlet.quizletandroid.ui.login.h(bVar, 12), pVar, pVar2);
    }

    public static p q(io.reactivex.rxjava3.functions.h hVar, p... pVarArr) {
        return pVarArr.length == 0 ? d(new NoSuchElementException()) : new w(5, pVarArr, hVar);
    }

    public final Object b() {
        io.reactivex.rxjava3.internal.observers.d dVar = new io.reactivex.rxjava3.internal.observers.d(1);
        j(dVar);
        return dVar.b();
    }

    public final io.reactivex.rxjava3.internal.operators.single.g e(io.reactivex.rxjava3.functions.h hVar) {
        Objects.requireNonNull(hVar, "mapper is null");
        return new io.reactivex.rxjava3.internal.operators.single.g(this, hVar, 0);
    }

    public final io.reactivex.rxjava3.internal.operators.single.g g(io.reactivex.rxjava3.functions.h hVar) {
        Objects.requireNonNull(hVar, "mapper is null");
        return new io.reactivex.rxjava3.internal.operators.single.g(this, hVar, 1);
    }

    public final io.reactivex.rxjava3.internal.operators.single.k h(o oVar) {
        Objects.requireNonNull(oVar, "scheduler is null");
        return new io.reactivex.rxjava3.internal.operators.single.k(this, oVar, 0);
    }

    public final io.reactivex.rxjava3.internal.observers.e i(io.reactivex.rxjava3.functions.d dVar, io.reactivex.rxjava3.functions.d dVar2) {
        Objects.requireNonNull(dVar, "onSuccess is null");
        Objects.requireNonNull(dVar2, "onError is null");
        io.reactivex.rxjava3.internal.observers.e eVar = new io.reactivex.rxjava3.internal.observers.e(1, dVar, dVar2);
        j(eVar);
        return eVar;
    }

    public final void j(q qVar) {
        Objects.requireNonNull(qVar, "observer is null");
        try {
            k(qVar);
        } catch (NullPointerException e) {
            throw e;
        } catch (Throwable th) {
            x7.b(th);
            NullPointerException nullPointerException = new NullPointerException("subscribeActual failed");
            nullPointerException.initCause(th);
            throw nullPointerException;
        }
    }

    public abstract void k(q qVar);

    public final io.reactivex.rxjava3.internal.operators.single.k l(o oVar) {
        Objects.requireNonNull(oVar, "scheduler is null");
        return new io.reactivex.rxjava3.internal.operators.single.k(this, oVar, 1);
    }

    /* JADX WARN: Multi-variable type inference failed */
    public final i m() {
        return this instanceof io.reactivex.rxjava3.internal.fuseable.a ? ((io.reactivex.rxjava3.internal.fuseable.a) this).c() : new com.jakewharton.rxbinding4.a(this, 8);
    }
}

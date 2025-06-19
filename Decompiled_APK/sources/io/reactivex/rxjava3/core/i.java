package io.reactivex.rxjava3.core;

import com.google.android.gms.internal.mlkit_vision_barcode.C7;
import com.google.android.gms.internal.mlkit_vision_barcode.x7;
import io.reactivex.rxjava3.internal.operators.observable.AbstractC4882a;
import io.reactivex.rxjava3.internal.operators.observable.B;
import io.reactivex.rxjava3.internal.operators.observable.C4884c;
import io.reactivex.rxjava3.internal.operators.observable.C4885d;
import io.reactivex.rxjava3.internal.operators.observable.C4896o;
import io.reactivex.rxjava3.internal.operators.observable.C4902v;
import io.reactivex.rxjava3.internal.operators.observable.E;
import io.reactivex.rxjava3.internal.operators.observable.H;
import io.reactivex.rxjava3.internal.operators.observable.J;
import io.reactivex.rxjava3.internal.operators.observable.W;
import io.reactivex.rxjava3.internal.operators.observable.Z;
import io.reactivex.rxjava3.internal.operators.observable.m0;
import java.util.Objects;
import java.util.concurrent.TimeUnit;

/* loaded from: classes3.dex */
public abstract class i implements k {
    public static i d(k kVar, i iVar, io.reactivex.rxjava3.functions.b bVar) {
        Objects.requireNonNull(kVar, "source1 is null");
        Objects.requireNonNull(iVar, "source2 is null");
        return f(new k[]{kVar, iVar}, new com.quizlet.quizletandroid.ui.login.h(bVar, 12), e.a);
    }

    public static i e(AbstractC4882a abstractC4882a, AbstractC4882a abstractC4882a2, i iVar, io.reactivex.rxjava3.functions.e eVar) {
        Objects.requireNonNull(abstractC4882a2, "source2 is null");
        return f(new k[]{abstractC4882a, abstractC4882a2, iVar}, new com.quizlet.quizletandroid.k(eVar, 18), e.a);
    }

    public static i f(k[] kVarArr, io.reactivex.rxjava3.functions.h hVar, int i) {
        if (kVarArr.length == 0) {
            return E.a;
        }
        io.reactivex.rxjava3.internal.functions.d.a(i, "bufferSize");
        return new C4896o(kVarArr, hVar, i << 1, 0);
    }

    public static io.reactivex.rxjava3.internal.operators.observable.r g(i iVar, i iVar2) {
        Objects.requireNonNull(iVar, "source1 is null");
        return new io.reactivex.rxjava3.internal.operators.observable.r(n(iVar, iVar2), e.a);
    }

    public static com.jakewharton.rxbinding4.a k(Throwable th) {
        Objects.requireNonNull(th, "throwable is null");
        return new com.jakewharton.rxbinding4.a(new io.reactivex.rxjava3.internal.functions.c(th), 5);
    }

    public static i n(Object... objArr) {
        Objects.requireNonNull(objArr, "items is null");
        return objArr.length == 0 ? E.a : objArr.length == 1 ? p(objArr[0]) : new com.jakewharton.rxbinding4.a(objArr, 6);
    }

    public static com.jakewharton.rxbinding4.a o(Iterable iterable) {
        Objects.requireNonNull(iterable, "source is null");
        return new com.jakewharton.rxbinding4.a(iterable, 7);
    }

    public static Z p(Object obj) {
        Objects.requireNonNull(obj, "item is null");
        return new Z(obj);
    }

    public static i r(i iVar, i iVar2) {
        return n(iVar, iVar2).m(io.reactivex.rxjava3.internal.functions.d.a, 2);
    }

    public static i y(i iVar, i iVar2, io.reactivex.rxjava3.functions.b bVar) {
        Objects.requireNonNull(iVar2, "source2 is null");
        com.quizlet.quizletandroid.ui.login.h hVar = new com.quizlet.quizletandroid.ui.login.h(bVar, 12);
        int i = e.a;
        k[] kVarArr = {iVar, iVar2};
        io.reactivex.rxjava3.internal.functions.d.a(i, "bufferSize");
        return new C4896o(kVarArr, hVar, i, 1);
    }

    @Override // io.reactivex.rxjava3.core.k
    public final void c(l lVar) {
        Objects.requireNonNull(lVar, "observer is null");
        try {
            v(lVar);
        } catch (NullPointerException e) {
            throw e;
        } catch (Throwable th) {
            x7.b(th);
            C7.c(th);
            NullPointerException nullPointerException = new NullPointerException("Actually not, but can't throw other exceptions due to RS");
            nullPointerException.initCause(th);
            throw nullPointerException;
        }
    }

    public final C4902v h(long j, TimeUnit timeUnit, o oVar) {
        Objects.requireNonNull(timeUnit, "unit is null");
        Objects.requireNonNull(oVar, "scheduler is null");
        return new C4902v(this, j, timeUnit, oVar);
    }

    public final B i(io.reactivex.rxjava3.functions.a aVar) {
        return new B(this, io.reactivex.rxjava3.internal.functions.d.d, new com.quizlet.quizletandroid.ui.setpage.terms.c(aVar, 10), aVar, io.reactivex.rxjava3.internal.functions.d.c);
    }

    public final C4885d j() {
        return new C4885d(this, null, 1);
    }

    public final C4884c l(io.reactivex.rxjava3.functions.i iVar) {
        Objects.requireNonNull(iVar, "predicate is null");
        return new C4884c(this, iVar, 1);
    }

    /* JADX WARN: Multi-variable type inference failed */
    public final i m(io.reactivex.rxjava3.functions.h hVar, int i) {
        int i2 = e.a;
        io.reactivex.rxjava3.internal.functions.d.a(i, "maxConcurrency");
        io.reactivex.rxjava3.internal.functions.d.a(i2, "bufferSize");
        if (!(this instanceof io.reactivex.rxjava3.operators.c)) {
            return new H(this, hVar, i, i2);
        }
        Object obj = ((io.reactivex.rxjava3.operators.c) this).get();
        return obj == null ? E.a : new io.reactivex.rxjava3.internal.operators.mixed.b(3, obj, hVar);
    }

    public final J q(io.reactivex.rxjava3.functions.h hVar) {
        Objects.requireNonNull(hVar, "mapper is null");
        return new J(this, hVar, 3);
    }

    public final W s(o oVar) {
        int i = e.a;
        Objects.requireNonNull(oVar, "scheduler is null");
        io.reactivex.rxjava3.internal.functions.d.a(i, "bufferSize");
        return new W(this, oVar, i, 1);
    }

    public final io.reactivex.rxjava3.disposables.b t() {
        return u(io.reactivex.rxjava3.internal.functions.d.d, io.reactivex.rxjava3.internal.functions.d.e, io.reactivex.rxjava3.internal.functions.d.c);
    }

    public final io.reactivex.rxjava3.disposables.b u(io.reactivex.rxjava3.functions.d dVar, io.reactivex.rxjava3.functions.d dVar2, io.reactivex.rxjava3.functions.a aVar) {
        Objects.requireNonNull(dVar, "onNext is null");
        Objects.requireNonNull(dVar2, "onError is null");
        Objects.requireNonNull(aVar, "onComplete is null");
        io.reactivex.rxjava3.internal.observers.h hVar = new io.reactivex.rxjava3.internal.observers.h(dVar, dVar2, aVar);
        c(hVar);
        return hVar;
    }

    public abstract void v(l lVar);

    public final m0 w(o oVar) {
        Objects.requireNonNull(oVar, "scheduler is null");
        return new m0(this, oVar, 0);
    }

    public final C4885d x(int i) {
        io.reactivex.rxjava3.internal.functions.d.a(i, "capacityHint");
        return new C4885d(this, i);
    }
}

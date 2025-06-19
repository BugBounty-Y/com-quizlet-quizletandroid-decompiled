package io.reactivex.rxjava3.internal.operators.maybe;

/* loaded from: classes3.dex */
public final class l extends io.reactivex.rxjava3.core.g implements io.reactivex.rxjava3.operators.c {
    public final Object a;

    public l(Object obj) {
        this.a = obj;
    }

    @Override // io.reactivex.rxjava3.core.g
    public final void f(io.reactivex.rxjava3.core.h hVar) {
        hVar.a(io.reactivex.rxjava3.internal.disposables.b.a);
        hVar.onSuccess(this.a);
    }

    @Override // io.reactivex.rxjava3.functions.j
    public final Object get() {
        return this.a;
    }
}

package io.reactivex.rxjava3.internal.operators.observable;

/* loaded from: classes3.dex */
public final class Z extends io.reactivex.rxjava3.core.i implements io.reactivex.rxjava3.operators.c {
    public final Object a;

    public Z(Object obj) {
        this.a = obj;
    }

    @Override // io.reactivex.rxjava3.functions.j
    public final Object get() {
        return this.a;
    }

    @Override // io.reactivex.rxjava3.core.i
    public final void v(io.reactivex.rxjava3.core.l lVar) {
        k0 k0Var = new k0(lVar, this.a);
        lVar.a(k0Var);
        k0Var.run();
    }
}

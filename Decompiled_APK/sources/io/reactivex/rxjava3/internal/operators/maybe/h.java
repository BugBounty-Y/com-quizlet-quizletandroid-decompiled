package io.reactivex.rxjava3.internal.operators.maybe;

import io.reactivex.rxjava3.internal.operators.observable.h0;

/* loaded from: classes3.dex */
public final class h extends io.reactivex.rxjava3.core.g {
    public final /* synthetic */ int a;
    public final Object b;
    public final Object c;

    public /* synthetic */ h(int i, Object obj, Object obj2) {
        this.a = i;
        this.b = obj;
        this.c = obj2;
    }

    @Override // io.reactivex.rxjava3.core.g
    public final void f(io.reactivex.rxjava3.core.h hVar) {
        switch (this.a) {
            case 0:
                ((io.reactivex.rxjava3.core.p) this.b).j(new g(hVar, (io.reactivex.rxjava3.functions.i) this.c, 0));
                break;
            case 1:
                ((io.reactivex.rxjava3.core.g) this.b).e(new i(hVar, (io.reactivex.rxjava3.functions.h) this.c, 0));
                break;
            case 2:
                ((io.reactivex.rxjava3.core.i) this.b).c(new h0(hVar, (io.reactivex.rxjava3.functions.b) this.c));
                break;
            default:
                ((io.reactivex.rxjava3.core.p) this.b).j(new i(hVar, (io.reactivex.rxjava3.functions.h) this.c, 1));
                break;
        }
    }
}

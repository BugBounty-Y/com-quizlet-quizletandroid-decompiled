package io.reactivex.rxjava3.internal.operators.observable;

/* loaded from: classes3.dex */
public final class N extends AbstractC4882a {
    public final io.reactivex.rxjava3.functions.h b;
    public final boolean c;

    public N(io.reactivex.rxjava3.core.i iVar, io.reactivex.rxjava3.functions.h hVar, boolean z) {
        super(iVar);
        this.b = hVar;
        this.c = z;
    }

    @Override // io.reactivex.rxjava3.core.i
    public final void v(io.reactivex.rxjava3.core.l lVar) {
        this.a.c(new M(lVar, this.b, this.c));
    }
}

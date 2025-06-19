package io.reactivex.rxjava3.internal.operators.observable;

/* renamed from: io.reactivex.rxjava3.internal.operators.observable.j, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4891j extends AbstractC4882a {
    public final int b;
    public final int c;

    public C4891j(U u, int i, int i2) {
        super(u);
        this.b = i;
        this.c = i2;
    }

    @Override // io.reactivex.rxjava3.core.i
    public final void v(io.reactivex.rxjava3.core.l lVar) {
        io.reactivex.rxjava3.core.k kVar = this.a;
        int i = this.c;
        int i2 = this.b;
        if (i != i2) {
            kVar.c(new C4890i(lVar, i2, i));
            return;
        }
        C4889h c4889h = new C4889h(lVar, i2);
        if (c4889h.c()) {
            kVar.c(c4889h);
        }
    }
}

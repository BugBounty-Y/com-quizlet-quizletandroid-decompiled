package io.reactivex.rxjava3.internal.operators.observable;

/* loaded from: classes3.dex */
public final class J extends AbstractC4882a {
    public final /* synthetic */ int b;
    public final io.reactivex.rxjava3.functions.h c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ J(io.reactivex.rxjava3.core.i iVar, io.reactivex.rxjava3.functions.h hVar, int i) {
        super(iVar);
        this.b = i;
        this.c = hVar;
    }

    @Override // io.reactivex.rxjava3.core.i
    public final void v(io.reactivex.rxjava3.core.l lVar) {
        switch (this.b) {
            case 0:
                this.a.c(new I(lVar, this.c));
                break;
            case 1:
                this.a.c(new O(lVar, this.c));
                break;
            case 2:
                this.a.c(new P(lVar, this.c, 0));
                break;
            case 3:
                this.a.c(new C4904x(lVar, this.c, 2));
                break;
            case 4:
                c0 c0Var = new c0(lVar, this.c);
                lVar.a(c0Var.c);
                this.a.c(c0Var);
                break;
            default:
                this.a.c(new P(lVar, this.c, 1));
                break;
        }
    }
}

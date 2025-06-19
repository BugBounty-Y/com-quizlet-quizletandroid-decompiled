package io.reactivex.rxjava3.internal.operators.observable;

/* loaded from: classes3.dex */
public final class o0 extends AbstractC4882a {
    public final /* synthetic */ int b;
    public final io.reactivex.rxjava3.core.i c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ o0(io.reactivex.rxjava3.core.i iVar, io.reactivex.rxjava3.core.i iVar2, int i) {
        super(iVar);
        this.b = i;
        this.c = iVar2;
    }

    @Override // io.reactivex.rxjava3.core.i
    public final void v(io.reactivex.rxjava3.core.l lVar) {
        switch (this.b) {
            case 0:
                n0 n0Var = new n0(lVar, this.c);
                lVar.a(n0Var.c);
                this.a.c(n0Var);
                break;
            default:
                t0 t0Var = new t0(lVar);
                lVar.a(t0Var);
                this.c.c(t0Var.c);
                this.a.c(t0Var);
                break;
        }
    }
}

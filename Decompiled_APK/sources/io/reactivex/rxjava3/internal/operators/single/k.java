package io.reactivex.rxjava3.internal.operators.single;

/* loaded from: classes3.dex */
public final class k extends io.reactivex.rxjava3.core.p {
    public final /* synthetic */ int a;
    public final io.reactivex.rxjava3.core.p b;
    public final io.reactivex.rxjava3.core.o c;

    public /* synthetic */ k(io.reactivex.rxjava3.core.p pVar, io.reactivex.rxjava3.core.o oVar, int i) {
        this.a = i;
        this.b = pVar;
        this.c = oVar;
    }

    @Override // io.reactivex.rxjava3.core.p
    public final void k(io.reactivex.rxjava3.core.q qVar) {
        switch (this.a) {
            case 0:
                this.b.j(new io.reactivex.rxjava3.internal.operators.maybe.q(qVar, this.c, 1));
                break;
            default:
                io.reactivex.rxjava3.internal.operators.completable.g gVar = new io.reactivex.rxjava3.internal.operators.completable.g(qVar, this.b);
                qVar.a(gVar);
                io.reactivex.rxjava3.disposables.b bVarB = this.c.b(gVar);
                io.reactivex.rxjava3.disposables.d dVar = (io.reactivex.rxjava3.disposables.d) gVar.c;
                dVar.getClass();
                io.reactivex.rxjava3.internal.disposables.a.c(dVar, bVarB);
                break;
        }
    }
}

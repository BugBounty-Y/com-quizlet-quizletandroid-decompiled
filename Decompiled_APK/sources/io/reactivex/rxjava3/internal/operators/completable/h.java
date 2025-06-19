package io.reactivex.rxjava3.internal.operators.completable;

import io.reactivex.rxjava3.core.o;

/* loaded from: classes3.dex */
public final class h extends io.reactivex.rxjava3.core.a {
    public final /* synthetic */ int a;
    public final io.reactivex.rxjava3.core.a b;
    public final o c;

    public /* synthetic */ h(io.reactivex.rxjava3.core.a aVar, o oVar, int i) {
        this.a = i;
        this.b = aVar;
        this.c = oVar;
    }

    @Override // io.reactivex.rxjava3.core.a
    public final void g(io.reactivex.rxjava3.core.b bVar) {
        switch (this.a) {
            case 0:
                this.b.b(new g(bVar, this.c));
                break;
            default:
                g gVar = new g(bVar, this.b);
                bVar.a(gVar);
                io.reactivex.rxjava3.disposables.b bVarB = this.c.b(gVar);
                io.reactivex.rxjava3.disposables.d dVar = (io.reactivex.rxjava3.disposables.d) gVar.c;
                dVar.getClass();
                io.reactivex.rxjava3.internal.disposables.a.c(dVar, bVarB);
                break;
        }
    }
}

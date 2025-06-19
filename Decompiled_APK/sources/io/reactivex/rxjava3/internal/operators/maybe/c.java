package io.reactivex.rxjava3.internal.operators.maybe;

/* loaded from: classes3.dex */
public final class c extends io.reactivex.rxjava3.core.e {
    public final /* synthetic */ int b;
    public final io.reactivex.rxjava3.core.g[] c;

    public /* synthetic */ c(io.reactivex.rxjava3.core.g[] gVarArr, int i) {
        this.b = i;
        this.c = gVarArr;
    }

    @Override // io.reactivex.rxjava3.core.e
    public final void b(io.reactivex.rxjava3.core.f fVar) {
        switch (this.b) {
            case 0:
                b bVar = new b(fVar, this.c);
                fVar.c(bVar);
                bVar.b();
                break;
            default:
                io.reactivex.rxjava3.core.g[] gVarArr = this.c;
                int length = gVarArr.length;
                n nVar = new n(fVar, length, length <= io.reactivex.rxjava3.core.e.a ? new o(length) : new m());
                fVar.c(nVar);
                io.reactivex.rxjava3.internal.util.b bVar2 = nVar.e;
                for (io.reactivex.rxjava3.core.g gVar : gVarArr) {
                    if (!nVar.g && bVar2.get() == null) {
                        gVar.e(nVar);
                    }
                }
                break;
        }
    }
}

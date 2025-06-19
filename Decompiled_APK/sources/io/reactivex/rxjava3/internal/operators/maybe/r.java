package io.reactivex.rxjava3.internal.operators.maybe;

/* loaded from: classes3.dex */
public final class r extends a {
    public final /* synthetic */ int b;
    public final io.reactivex.rxjava3.core.o c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ r(io.reactivex.rxjava3.core.g gVar, io.reactivex.rxjava3.core.o oVar, int i) {
        super(gVar);
        this.b = i;
        this.c = oVar;
    }

    @Override // io.reactivex.rxjava3.core.g
    public final void f(io.reactivex.rxjava3.core.h hVar) {
        switch (this.b) {
            case 0:
                this.a.e(new q(hVar, this.c, 0));
                break;
            default:
                io.reactivex.rxjava3.internal.observers.e eVar = new io.reactivex.rxjava3.internal.observers.e(hVar);
                hVar.a(eVar);
                io.reactivex.rxjava3.disposables.b bVarB = this.c.b(new com.google.android.gms.tasks.k(eVar, false, this.a, 6));
                io.reactivex.rxjava3.disposables.d dVar = (io.reactivex.rxjava3.disposables.d) eVar.b;
                dVar.getClass();
                io.reactivex.rxjava3.internal.disposables.a.c(dVar, bVarB);
                break;
        }
    }
}

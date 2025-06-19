package io.reactivex.rxjava3.internal.operators.maybe;

/* loaded from: classes3.dex */
public final class j extends a {
    public final /* synthetic */ int b;
    public final io.reactivex.rxjava3.functions.h c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ j(io.reactivex.rxjava3.core.g gVar, io.reactivex.rxjava3.functions.h hVar, int i) {
        super(gVar);
        this.b = i;
        this.c = hVar;
    }

    @Override // io.reactivex.rxjava3.core.g
    public final void f(io.reactivex.rxjava3.core.h hVar) {
        switch (this.b) {
            case 0:
                this.a.e(new io.reactivex.rxjava3.internal.operators.completable.l(hVar, this.c));
                break;
            default:
                this.a.e(new com.quizlet.infra.legacysyncengine.datasources.s(5, hVar, this.c));
                break;
        }
    }
}

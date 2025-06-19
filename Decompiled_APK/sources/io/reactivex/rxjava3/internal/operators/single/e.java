package io.reactivex.rxjava3.internal.operators.single;

import com.quizlet.infra.legacysyncengine.datasources.s;

/* loaded from: classes3.dex */
public final class e extends io.reactivex.rxjava3.core.p {
    public final /* synthetic */ int a;
    public final io.reactivex.rxjava3.core.p b;
    public final io.reactivex.rxjava3.functions.a c;

    public /* synthetic */ e(io.reactivex.rxjava3.core.p pVar, io.reactivex.rxjava3.functions.a aVar, int i) {
        this.a = i;
        this.b = pVar;
        this.c = aVar;
    }

    @Override // io.reactivex.rxjava3.core.p
    public final void k(io.reactivex.rxjava3.core.q qVar) {
        switch (this.a) {
            case 0:
                this.b.j(new s(9, qVar, this.c));
                break;
            default:
                this.b.j(new io.reactivex.rxjava3.internal.operators.completable.e(qVar, this.c, 2));
                break;
        }
    }
}

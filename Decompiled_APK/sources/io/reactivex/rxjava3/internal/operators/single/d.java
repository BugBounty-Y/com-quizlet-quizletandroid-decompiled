package io.reactivex.rxjava3.internal.operators.single;

import com.google.android.gms.internal.measurement.C3083y1;
import com.quizlet.infra.legacysyncengine.datasources.s;

/* loaded from: classes3.dex */
public final class d extends io.reactivex.rxjava3.core.p {
    public final /* synthetic */ int a;
    public final io.reactivex.rxjava3.core.p b;
    public final io.reactivex.rxjava3.functions.d c;

    public /* synthetic */ d(io.reactivex.rxjava3.core.p pVar, io.reactivex.rxjava3.functions.d dVar, int i) {
        this.a = i;
        this.b = pVar;
        this.c = dVar;
    }

    @Override // io.reactivex.rxjava3.core.p
    public final void k(io.reactivex.rxjava3.core.q qVar) {
        switch (this.a) {
            case 0:
                this.b.j(new s(8, qVar, this.c));
                break;
            case 1:
                this.b.j(new C3083y1(9, qVar, this.c));
                break;
            default:
                this.b.j(new com.quizlet.remote.model.user.a(this, qVar));
                break;
        }
    }
}

package io.reactivex.rxjava3.internal.operators.maybe;

import java.util.Objects;

/* loaded from: classes3.dex */
public final class w extends io.reactivex.rxjava3.core.p {
    public final /* synthetic */ int a;
    public final Object b;
    public final Object c;

    public /* synthetic */ w(int i, Object obj, Object obj2) {
        this.a = i;
        this.b = obj;
        this.c = obj2;
    }

    @Override // io.reactivex.rxjava3.core.p
    public final void k(io.reactivex.rxjava3.core.q qVar) {
        switch (this.a) {
            case 0:
                ((io.reactivex.rxjava3.core.g) this.b).e(new com.quizlet.infra.legacysyncengine.datasources.s(7, qVar, this.c));
                break;
            case 1:
                ((io.reactivex.rxjava3.core.a) this.c).b(new io.reactivex.rxjava3.internal.observers.e(6, qVar, (io.reactivex.rxjava3.core.p) this.b));
                break;
            case 2:
                ((io.reactivex.rxjava3.subjects.r) this.b).j(new io.reactivex.rxjava3.internal.observers.e(qVar, (com.quizlet.eventlogger.e) this.c));
                break;
            case 3:
                ((w) this.b).j(new com.quizlet.remote.model.union.folderwithcreator.b(this, qVar));
                break;
            case 4:
                io.reactivex.rxjava3.internal.observers.e eVar = new io.reactivex.rxjava3.internal.observers.e(qVar);
                qVar.a(eVar);
                io.reactivex.rxjava3.internal.operators.flowable.c cVar = (io.reactivex.rxjava3.internal.operators.flowable.c) this.c;
                io.reactivex.rxjava3.internal.operators.completable.k kVar = (io.reactivex.rxjava3.internal.operators.completable.k) eVar.c;
                if (kVar != null) {
                    cVar.a(kVar);
                } else {
                    Objects.requireNonNull(kVar, "subscriber is null");
                    cVar.a(new io.reactivex.rxjava3.internal.subscribers.a(kVar));
                }
                ((io.reactivex.rxjava3.internal.operators.single.k) this.b).j(eVar);
                break;
            default:
                io.reactivex.rxjava3.core.p[] pVarArr = (io.reactivex.rxjava3.core.p[]) this.b;
                int length = pVarArr.length;
                if (length == 1) {
                    pVarArr[0].j(new com.quizlet.remote.model.user.emailconfirmation.c(qVar, new com.quizlet.login.common.interactors.d(this, 17)));
                    break;
                } else {
                    io.reactivex.rxjava3.internal.operators.single.p pVar = new io.reactivex.rxjava3.internal.operators.single.p(length, qVar, (io.reactivex.rxjava3.functions.h) this.c);
                    qVar.a(pVar);
                    for (int i = 0; i < length && !pVar.b(); i++) {
                        io.reactivex.rxjava3.core.p pVar2 = pVarArr[i];
                        if (pVar2 == null) {
                            pVar.a(i, new NullPointerException("One of the sources is null"));
                            break;
                        } else {
                            pVar2.j(pVar.c[i]);
                        }
                    }
                }
        }
    }
}

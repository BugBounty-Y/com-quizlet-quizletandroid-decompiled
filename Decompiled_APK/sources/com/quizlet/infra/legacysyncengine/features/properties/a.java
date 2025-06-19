package com.quizlet.infra.legacysyncengine.features.properties;

import com.quizlet.infra.legacysyncengine.datasources.q;
import io.reactivex.rxjava3.core.j;
import io.reactivex.rxjava3.internal.operators.observable.C4899s;
import kotlin.collections.Z;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final /* synthetic */ class a implements j {
    public final /* synthetic */ int a;
    public final /* synthetic */ d b;
    public final /* synthetic */ com.quizlet.infra.legacysyncengine.orm.query.a c;

    public /* synthetic */ a(d dVar, com.quizlet.infra.legacysyncengine.orm.query.a aVar, int i) {
        this.a = i;
        this.b = dVar;
        this.c = aVar;
    }

    @Override // io.reactivex.rxjava3.core.j
    public final void l(C4899s emitter) {
        switch (this.a) {
            case 0:
                Intrinsics.checkNotNullParameter(emitter, "emitter");
                q qVar = new q(emitter, 3);
                d dVar = this.b;
                com.quizlet.infra.legacysyncengine.net.c cVar = dVar.a;
                com.quizlet.infra.legacysyncengine.orm.query.a aVar = this.c;
                cVar.e(aVar, qVar);
                emitter.d(new b(dVar, aVar, qVar, 0));
                dVar.a.c(aVar, Z.b(com.quizlet.infra.legacysyncengine.net.b.a));
                break;
            default:
                Intrinsics.checkNotNullParameter(emitter, "emitter");
                q qVar2 = new q(emitter, 4);
                d dVar2 = this.b;
                com.quizlet.infra.legacysyncengine.net.c cVar2 = dVar2.a;
                com.quizlet.infra.legacysyncengine.orm.query.a aVar2 = this.c;
                cVar2.e(aVar2, qVar2);
                emitter.d(new b(dVar2, aVar2, qVar2, 1));
                dVar2.a.c(aVar2, Z.b(com.quizlet.infra.legacysyncengine.net.b.a));
                break;
        }
    }
}

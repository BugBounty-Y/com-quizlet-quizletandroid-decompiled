package com.quizlet.quizletandroid.config.features.properties;

import com.onetrust.otpublishers.headless.UI.fragment.q;
import com.quizlet.db.data.models.persisted.base.Models;
import com.quizlet.db.data.models.persisted.fields.DBGroupFields;
import com.quizlet.db.data.models.persisted.fields.DBGroupMembershipFields;
import io.reactivex.rxjava3.core.j;
import io.reactivex.rxjava3.internal.operators.observable.C4887f;
import io.reactivex.rxjava3.internal.operators.observable.C4899s;
import kotlin.collections.Z;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class b {
    public final io.reactivex.rxjava3.internal.operators.single.b a;
    public final io.reactivex.rxjava3.internal.operators.single.b b;

    public b(long j, long j2, com.quizlet.infra.legacysyncengine.net.c loader) {
        Intrinsics.checkNotNullParameter(loader, "loader");
        final q qVar = new q(loader);
        com.quizlet.infra.legacysyncengine.orm.b bVar = new com.quizlet.infra.legacysyncengine.orm.b(Models.GROUP);
        bVar.b(Long.valueOf(j), DBGroupFields.ID);
        final com.quizlet.infra.legacysyncengine.orm.query.a aVarA = bVar.a();
        final int i = 0;
        io.reactivex.rxjava3.internal.operators.flowable.b bVar2 = new io.reactivex.rxjava3.internal.operators.flowable.b(new C4887f(new com.jakewharton.rxbinding4.a(new j() { // from class: com.quizlet.quizletandroid.config.features.properties.c
            @Override // io.reactivex.rxjava3.core.j
            public final void l(C4899s emitter) {
                switch (i) {
                    case 0:
                        Intrinsics.checkNotNullParameter(emitter, "emitter");
                        com.quizlet.infra.legacysyncengine.datasources.q qVar2 = new com.quizlet.infra.legacysyncengine.datasources.q(emitter, 6);
                        q qVar3 = qVar;
                        com.quizlet.infra.legacysyncengine.orm.query.a aVar = aVarA;
                        com.quizlet.infra.legacysyncengine.net.c cVar = (com.quizlet.infra.legacysyncengine.net.c) qVar3.b;
                        cVar.e(aVar, qVar2);
                        emitter.d(new com.quizlet.infra.legacysyncengine.features.properties.b(qVar3, aVar, qVar2, 4));
                        cVar.c(aVar, Z.b(com.quizlet.infra.legacysyncengine.net.b.a));
                        break;
                    default:
                        Intrinsics.checkNotNullParameter(emitter, "emitter");
                        com.quizlet.infra.legacysyncengine.datasources.q qVar4 = new com.quizlet.infra.legacysyncengine.datasources.q(emitter, 7);
                        q qVar5 = qVar;
                        com.quizlet.infra.legacysyncengine.orm.query.a aVar2 = aVarA;
                        com.quizlet.infra.legacysyncengine.net.c cVar2 = (com.quizlet.infra.legacysyncengine.net.c) qVar5.b;
                        cVar2.e(aVar2, qVar4);
                        emitter.d(new com.quizlet.infra.legacysyncengine.features.properties.b(qVar5, aVar2, qVar4, 5));
                        cVar2.c(aVar2, Z.b(com.quizlet.infra.legacysyncengine.net.b.a));
                        break;
                }
            }
        }, 3).l(a.f).q(a.g), 5), 2);
        Intrinsics.checkNotNullExpressionValue(bVar2, "singleOrError(...)");
        this.a = new io.reactivex.rxjava3.internal.operators.single.b(bVar2);
        com.quizlet.infra.legacysyncengine.orm.b bVar3 = new com.quizlet.infra.legacysyncengine.orm.b(Models.GROUP_MEMBERSHIP);
        bVar3.b(Long.valueOf(j2), DBGroupMembershipFields.USER);
        bVar3.b(Long.valueOf(j), DBGroupMembershipFields.CLASS);
        final com.quizlet.infra.legacysyncengine.orm.query.a aVarA2 = bVar3.a();
        final int i2 = 1;
        io.reactivex.rxjava3.internal.operators.flowable.b bVar4 = new io.reactivex.rxjava3.internal.operators.flowable.b(new C4887f(new com.jakewharton.rxbinding4.a(new j() { // from class: com.quizlet.quizletandroid.config.features.properties.c
            @Override // io.reactivex.rxjava3.core.j
            public final void l(C4899s emitter) {
                switch (i2) {
                    case 0:
                        Intrinsics.checkNotNullParameter(emitter, "emitter");
                        com.quizlet.infra.legacysyncengine.datasources.q qVar2 = new com.quizlet.infra.legacysyncengine.datasources.q(emitter, 6);
                        q qVar3 = qVar;
                        com.quizlet.infra.legacysyncengine.orm.query.a aVar = aVarA2;
                        com.quizlet.infra.legacysyncengine.net.c cVar = (com.quizlet.infra.legacysyncengine.net.c) qVar3.b;
                        cVar.e(aVar, qVar2);
                        emitter.d(new com.quizlet.infra.legacysyncengine.features.properties.b(qVar3, aVar, qVar2, 4));
                        cVar.c(aVar, Z.b(com.quizlet.infra.legacysyncengine.net.b.a));
                        break;
                    default:
                        Intrinsics.checkNotNullParameter(emitter, "emitter");
                        com.quizlet.infra.legacysyncengine.datasources.q qVar4 = new com.quizlet.infra.legacysyncengine.datasources.q(emitter, 7);
                        q qVar5 = qVar;
                        com.quizlet.infra.legacysyncengine.orm.query.a aVar2 = aVarA2;
                        com.quizlet.infra.legacysyncengine.net.c cVar2 = (com.quizlet.infra.legacysyncengine.net.c) qVar5.b;
                        cVar2.e(aVar2, qVar4);
                        emitter.d(new com.quizlet.infra.legacysyncengine.features.properties.b(qVar5, aVar2, qVar4, 5));
                        cVar2.c(aVar2, Z.b(com.quizlet.infra.legacysyncengine.net.b.a));
                        break;
                }
            }
        }, 3).l(a.h).q(a.i), 5), 2);
        Intrinsics.checkNotNullExpressionValue(bVar4, "singleOrError(...)");
        this.b = new io.reactivex.rxjava3.internal.operators.single.b(bVar4);
    }
}

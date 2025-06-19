package com.quizlet.shared.persistence.studiableMetadata;

import androidx.glance.appwidget.protobuf.Z;
import assistantMode.enums.q;
import assistantMode.enums.s;
import assistantMode.refactored.enums.j;
import assistantMode.refactored.types.StudiableMetadataContent;
import com.quizlet.shared.persistence.db.g;
import java.util.List;
import kotlin.Unit;
import kotlin.collections.K;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class b extends i implements Function2 {
    public final /* synthetic */ e j;
    public final /* synthetic */ com.quizlet.shared.models.api.keys.b k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b(e eVar, com.quizlet.shared.models.api.keys.b bVar, h hVar) {
        super(2, hVar);
        this.j = eVar;
        this.k = bVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        return new b(this.j, this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((b) create((C) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        List list;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        g gVar = (g) this.j.a.getValue();
        com.quizlet.shared.models.api.keys.b bVar = this.k;
        long j = bVar.a;
        j studiableContainerType = j.b;
        gVar.getClass();
        Intrinsics.checkNotNullParameter(studiableContainerType, "studiableContainerType");
        s studiableMetadataType = bVar.b;
        Intrinsics.checkNotNullParameter(studiableMetadataType, "studiableMetadataType");
        com.quizlet.shared.persistence.db.a mapper = com.quizlet.shared.persistence.db.a.c;
        Intrinsics.checkNotNullParameter(studiableContainerType, "studiableContainerType");
        Intrinsics.checkNotNullParameter(studiableMetadataType, "studiableMetadataType");
        Intrinsics.checkNotNullParameter(mapper, "mapper");
        com.quizlet.shared.persistence.db.c cVar = new com.quizlet.shared.persistence.db.c(gVar, j, studiableMetadataType, new com.quizlet.shared.persistence.db.f(gVar, 0));
        androidx.credentials.playservices.controllers.BeginSignIn.c mapper2 = new androidx.credentials.playservices.controllers.BeginSignIn.c(cVar, 8);
        Intrinsics.checkNotNullParameter(mapper2, "mapper");
        g gVar2 = cVar.f;
        com.quizlet.shared.persistence.db.h hVar = (com.quizlet.shared.persistence.db.h) ((app.cash.sqldelight.driver.android.i) gVar2.b).f(-1797753035, "SELECT model\n    FROM dbStudiableMetadata\n    WHERE (\n        studiableContainerId = ?\n        AND studiableContainerType = ?\n        AND studiableMetadataType = ?\n    )", mapper2, 3, new androidx.compose.ui.viewinterop.b(25, cVar, gVar2)).b;
        if (hVar == null || (list = hVar.a) == null) {
            list = K.a;
        }
        return new StudiableMetadataContent(list, q.d);
    }
}

package com.quizlet.features.setpage.offline;

import androidx.glance.appwidget.protobuf.Z;
import androidx.work.impl.model.l;
import com.google.android.gms.internal.mlkit_vision_camera.I1;
import com.quizlet.db.data.models.persisted.DBOfflineEntity;
import com.quizlet.db.data.models.persisted.base.Models;
import com.quizlet.db.data.models.persisted.fields.DBStudySetFields;
import com.quizlet.generated.enums.G1;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class j extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ k k;
    public final /* synthetic */ long l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public j(k kVar, long j, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = kVar;
        this.l = j;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new j(this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((j) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        boolean z = false;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            com.quizlet.offline.managers.i iVar = (com.quizlet.offline.managers.i) this.k.c;
            iVar.getClass();
            com.quizlet.features.infra.models.b offlineStatus = com.quizlet.features.infra.models.b.b;
            com.quizlet.local.ormlite.models.term.b bVar = iVar.g;
            Intrinsics.checkNotNullParameter(offlineStatus, "offlineStatus");
            long j = this.l;
            ((com.quizlet.infra.legacysyncengine.managers.i) bVar.b).c(DBOfflineEntity.create(Long.valueOf(j), G1.SET, 1));
            iVar.j.put(Long.valueOf(j), offlineStatus);
            com.quizlet.infra.legacysyncengine.orm.b bVar2 = new com.quizlet.infra.legacysyncengine.orm.b(Models.STUDY_SET);
            bVar2.b(Long.valueOf(j), DBStudySetFields.ID);
            io.reactivex.rxjava3.internal.operators.completable.a aVar2 = new io.reactivex.rxjava3.internal.operators.completable.a(5, iVar.d.n().e(new l(iVar, z, new com.quizlet.qutils.data.offline.d(bVar2.a(), com.quizlet.qutils.data.offline.c.a, true, com.quizlet.qutils.data.offline.b.a, com.quizlet.qutils.data.offline.a.b), 24)).h(iVar.c), new com.quizlet.data.interactor.course.a(iVar, 23));
            Intrinsics.checkNotNullExpressionValue(aVar2, "flatMapCompletable(...)");
            this.j = 1;
            if (I1.a(aVar2, this) == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
        }
        return Unit.a;
    }
}

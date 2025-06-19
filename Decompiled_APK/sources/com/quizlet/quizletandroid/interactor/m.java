package com.quizlet.quizletandroid.interactor;

import androidx.datastore.core.C1087t;
import androidx.paging.J0;
import com.quizlet.data.model.I;
import com.quizlet.data.model.S1;
import com.quizlet.data.model.Y1;
import com.quizlet.db.data.models.persisted.DBStudySet;
import com.quizlet.db.data.models.persisted.DBUser;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.AbstractC5040y;
import kotlinx.coroutines.flow.InterfaceC4992i;
import kotlinx.coroutines.flow.e0;

/* loaded from: classes3.dex */
public final class m {
    public final long a;
    public final com.quizlet.infra.legacysyncengine.net.c b;
    public final AbstractC5040y c;

    public m(long j, com.quizlet.infra.legacysyncengine.net.c loader, assistantMode.utils.studiableMetadata.b userMapper, AbstractC5040y ioDispatcher) {
        Intrinsics.checkNotNullParameter(loader, "loader");
        Intrinsics.checkNotNullParameter(userMapper, "userMapper");
        Intrinsics.checkNotNullParameter(ioDispatcher, "ioDispatcher");
        this.a = j;
        this.b = loader;
        this.c = ioDispatcher;
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0016  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.io.Serializable a(com.quizlet.quizletandroid.interactor.m r7, kotlin.coroutines.jvm.internal.c r8) {
        /*
            r7.getClass()
            boolean r0 = r8 instanceof com.quizlet.quizletandroid.interactor.g
            if (r0 == 0) goto L16
            r0 = r8
            com.quizlet.quizletandroid.interactor.g r0 = (com.quizlet.quizletandroid.interactor.g) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L16
            int r1 = r1 - r2
            r0.m = r1
            goto L1b
        L16:
            com.quizlet.quizletandroid.interactor.g r0 = new com.quizlet.quizletandroid.interactor.g
            r0.<init>(r7, r8)
        L1b:
            java.lang.Object r8 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 1
            if (r2 == 0) goto L34
            if (r2 != r3) goto L2c
            com.quizlet.quizletandroid.interactor.m r7 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r8)
            goto L73
        L2c:
            java.lang.IllegalStateException r7 = new java.lang.IllegalStateException
            java.lang.String r8 = "call to 'resume' before 'invoke' with coroutine"
            r7.<init>(r8)
            throw r7
        L34:
            androidx.glance.appwidget.protobuf.Z.e(r8)
            com.quizlet.infra.legacysyncengine.orm.b r8 = new com.quizlet.infra.legacysyncengine.orm.b
            com.quizlet.db.data.models.persisted.base.ModelType<com.quizlet.db.data.models.persisted.DBOfflineEntity> r2 = com.quizlet.db.data.models.persisted.base.Models.OFFLINE_ENTITY
            r8.<init>(r2)
            com.quizlet.db.data.models.base.ModelField<com.quizlet.db.data.models.persisted.DBOfflineEntity, java.lang.Long> r2 = com.quizlet.db.data.models.persisted.fields.DBOfflineEntityFields.OFFLINE_STATUS
            com.quizlet.features.infra.models.b r4 = com.quizlet.features.infra.models.b.b
            r4 = 2
            long r4 = (long) r4
            java.lang.Long r6 = new java.lang.Long
            r6.<init>(r4)
            r8.b(r6, r2)
            com.quizlet.db.data.orm.Relationship<com.quizlet.db.data.models.persisted.DBOfflineEntity, com.quizlet.db.data.models.interfaces.StudyableModel> r2 = com.quizlet.db.data.models.persisted.fields.DBOfflineEntityFields.STUDYABLE
            com.quizlet.db.data.orm.Relationship<com.quizlet.db.data.models.persisted.DBStudySet, com.quizlet.db.data.models.persisted.DBUser> r4 = com.quizlet.db.data.models.persisted.fields.DBStudySetFields.CREATOR
            com.quizlet.db.data.orm.Relationship[] r2 = new com.quizlet.db.data.orm.Relationship[]{r2, r4}
            r8.e(r2)
            com.quizlet.infra.legacysyncengine.orm.query.a r8 = r8.a()
            com.quizlet.infra.legacysyncengine.net.b r2 = com.quizlet.infra.legacysyncengine.net.b.a
            com.quizlet.infra.legacysyncengine.net.c r4 = r7.b
            io.reactivex.rxjava3.internal.operators.flowable.b r8 = r4.b(r8, r2)
            java.lang.String r2 = "databaseFetch(...)"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r8, r2)
            r0.j = r7
            r0.m = r3
            java.lang.Object r8 = com.google.android.gms.internal.mlkit_vision_camera.I1.b(r8, r0)
            if (r8 != r1) goto L73
            return r1
        L73:
            java.lang.String r0 = "await(...)"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r8, r0)
            java.lang.Iterable r8 = (java.lang.Iterable) r8
            java.util.ArrayList r0 = new java.util.ArrayList
            r0.<init>()
            java.util.Iterator r8 = r8.iterator()
        L83:
            boolean r1 = r8.hasNext()
            if (r1 == 0) goto L9a
            java.lang.Object r1 = r8.next()
            r2 = r1
            com.quizlet.db.data.models.persisted.DBOfflineEntity r2 = (com.quizlet.db.data.models.persisted.DBOfflineEntity) r2
            boolean r2 = r2.getDeleted()
            if (r2 != 0) goto L83
            r0.add(r1)
            goto L83
        L9a:
            java.util.ArrayList r8 = new java.util.ArrayList
            r1 = 10
            int r1 = kotlin.collections.C.q(r0, r1)
            r8.<init>(r1)
            java.util.Iterator r0 = r0.iterator()
        La9:
            boolean r1 = r0.hasNext()
            if (r1 == 0) goto Lce
            java.lang.Object r1 = r0.next()
            com.quizlet.db.data.models.persisted.DBOfflineEntity r1 = (com.quizlet.db.data.models.persisted.DBOfflineEntity) r1
            com.quizlet.db.data.models.interfaces.StudyableModel r1 = r1.getStudyableModel()
            java.lang.String r2 = "null cannot be cast to non-null type com.quizlet.db.data.models.persisted.DBStudySet"
            kotlin.jvm.internal.Intrinsics.e(r1, r2)
            com.quizlet.db.data.models.persisted.DBStudySet r1 = (com.quizlet.db.data.models.persisted.DBStudySet) r1
            com.quizlet.data.model.Y1 r2 = com.quizlet.data.model.Y1.d
            long r3 = r1.getSortTimestamp()
            com.quizlet.data.model.S1 r1 = r7.c(r1, r2, r3)
            r8.add(r1)
            goto La9
        Lce:
            return r8
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.quizletandroid.interactor.m.a(com.quizlet.quizletandroid.interactor.m, kotlin.coroutines.jvm.internal.c):java.io.Serializable");
    }

    public final InterfaceC4992i b() {
        return e0.s(e0.m(new J0(new C1087t(new l(this, null)), new com.quizlet.data.interactor.folderwithcreator.b(3, 4, null))), this.c);
    }

    public final S1 c(DBStudySet dBStudySet, Y1 y1, long j) {
        long id = dBStudySet.getSet().getId();
        String title = dBStudySet.getSet().getTitle();
        if (title == null) {
            title = "";
        }
        I i = new I(id, title, dBStudySet.getSet().getNumTerms(), dBStudySet.getSet().getHasImages(), dBStudySet.getSet().getHasDiagrams(), dBStudySet.getSet().isVisibilityRestricted(), !dBStudySet.getSet().getIsCreated(), j, y1, dBStudySet.getAcccessCodePrefix(), dBStudySet.getPasswordUse(), dBStudySet.getAccessType(), dBStudySet.getDeleted(), dBStudySet.getPublishedTimestamp(), dBStudySet.getTimestamp(), dBStudySet.getThumbnailUrl());
        DBUser creator = dBStudySet.getSet().getCreator();
        if (creator != null) {
            return new S1(i, assistantMode.utils.studiableMetadata.b.O(creator));
        }
        throw new IllegalStateException("Creator is null");
    }
}

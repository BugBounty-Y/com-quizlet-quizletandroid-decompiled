package com.quizlet.shared.repository;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class j implements c {
    public final com.quizlet.shared.quizletapi.studiableMetadata.a a;
    public final com.quizlet.shared.persistence.studiableMetadata.f b;

    public j(com.quizlet.shared.quizletapi.studiableMetadata.a remoteService, com.quizlet.shared.persistence.studiableMetadata.f persistenceStore) {
        Intrinsics.checkNotNullParameter(remoteService, "service");
        Intrinsics.checkNotNullParameter(persistenceStore, "persistenceStore");
        Intrinsics.checkNotNullParameter(remoteService, "remoteService");
        Intrinsics.checkNotNullParameter(persistenceStore, "persistenceStore");
        this.a = remoteService;
        this.b = persistenceStore;
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static java.lang.Object b(com.quizlet.shared.repository.j r6, com.quizlet.shared.models.api.keys.b r7, kotlin.coroutines.jvm.internal.c r8) {
        /*
            boolean r0 = r8 instanceof com.quizlet.shared.repository.base.b
            if (r0 == 0) goto L13
            r0 = r8
            com.quizlet.shared.repository.base.b r0 = (com.quizlet.shared.repository.base.b) r0
            int r1 = r0.n
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.n = r1
            goto L18
        L13:
            com.quizlet.shared.repository.base.b r0 = new com.quizlet.shared.repository.base.b
            r0.<init>(r6, r8)
        L18:
            java.lang.Object r8 = r0.l
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.n
            r3 = 3
            r4 = 2
            r5 = 1
            if (r2 == 0) goto L41
            if (r2 == r5) goto L39
            if (r2 == r4) goto L35
            if (r2 != r3) goto L2d
            androidx.glance.appwidget.protobuf.Z.e(r8)
            return r8
        L2d:
            java.lang.IllegalStateException r6 = new java.lang.IllegalStateException
            java.lang.String r7 = "call to 'resume' before 'invoke' with coroutine"
            r6.<init>(r7)
            throw r6
        L35:
            androidx.glance.appwidget.protobuf.Z.e(r8)
            return r8
        L39:
            com.quizlet.shared.models.api.keys.b r7 = r0.k
            com.quizlet.shared.repository.j r6 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r8)
            goto L53
        L41:
            androidx.glance.appwidget.protobuf.Z.e(r8)
            com.quizlet.shared.persistence.studiableMetadata.f r8 = r6.b
            r0.j = r6
            r0.k = r7
            r0.n = r5
            java.lang.Object r8 = r8.b(r7, r0)
            if (r8 != r1) goto L53
            goto L85
        L53:
            r2 = 0
            if (r7 == 0) goto L71
            if (r8 == 0) goto L71
            r5 = r8
            assistantMode.refactored.types.StudiableMetadataContent r5 = (assistantMode.refactored.types.StudiableMetadataContent) r5
            java.util.List r5 = r5.a
            boolean r5 = r5.isEmpty()
            if (r5 == 0) goto L71
            r0.j = r2
            r0.k = r2
            r0.n = r4
            java.io.Serializable r6 = r6.a(r7, r0)
            if (r6 != r1) goto L70
            goto L85
        L70:
            return r6
        L71:
            if (r8 == 0) goto L79
            kotlin.r r6 = new kotlin.r
            r6.<init>(r8)
            return r6
        L79:
            r0.j = r2
            r0.k = r2
            r0.n = r3
            java.io.Serializable r6 = r6.a(r7, r0)
            if (r6 != r1) goto L86
        L85:
            return r1
        L86:
            return r6
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.shared.repository.j.b(com.quizlet.shared.repository.j, com.quizlet.shared.models.api.keys.b, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Code restructure failed: missing block: B:27:0x006b, code lost:
    
        if (r9 == r1) goto L28;
     */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.io.Serializable a(com.quizlet.shared.models.api.keys.b r8, kotlin.coroutines.jvm.internal.c r9) {
        /*
            r7 = this;
            boolean r0 = r9 instanceof com.quizlet.shared.repository.base.a
            if (r0 == 0) goto L13
            r0 = r9
            com.quizlet.shared.repository.base.a r0 = (com.quizlet.shared.repository.base.a) r0
            int r1 = r0.n
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.n = r1
            goto L18
        L13:
            com.quizlet.shared.repository.base.a r0 = new com.quizlet.shared.repository.base.a
            r0.<init>(r7, r9)
        L18:
            java.lang.Object r9 = r0.l
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.n
            r3 = 2
            r4 = 1
            if (r2 == 0) goto L3a
            if (r2 == r4) goto L32
            if (r2 != r3) goto L2a
            androidx.glance.appwidget.protobuf.Z.e(r9)
            goto L6e
        L2a:
            java.lang.IllegalStateException r8 = new java.lang.IllegalStateException
            java.lang.String r9 = "call to 'resume' before 'invoke' with coroutine"
            r8.<init>(r9)
            throw r8
        L32:
            com.quizlet.shared.models.api.keys.b r8 = r0.k
            com.quizlet.shared.repository.j r2 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r9)
            goto L4f
        L3a:
            androidx.glance.appwidget.protobuf.Z.e(r9)
            r0.j = r7
            r0.k = r8
            r0.n = r4
            com.quizlet.shared.quizletapi.studiableMetadata.a r9 = r7.a
            com.quizlet.shared.quizletapi.studiableMetadata.d r9 = (com.quizlet.shared.quizletapi.studiableMetadata.d) r9
            java.io.Serializable r9 = r9.a(r8, r0)
            if (r9 != r1) goto L4e
            goto L6d
        L4e:
            r2 = r7
        L4f:
            kotlin.r r9 = (kotlin.r) r9
            if (r9 == 0) goto L74
            java.lang.Object r4 = r9.a
            boolean r5 = r4 instanceof kotlin.q
            r6 = 0
            if (r5 == 0) goto L5b
            r4 = r6
        L5b:
            if (r4 == 0) goto L74
            kotlin.p r9 = kotlin.r.b
            com.quizlet.shared.persistence.studiableMetadata.f r9 = r2.b
            r0.j = r6
            r0.k = r6
            r0.n = r3
            java.lang.Object r9 = r9.a(r8, r4, r0)
            if (r9 != r1) goto L6e
        L6d:
            return r1
        L6e:
            kotlin.r r8 = new kotlin.r
            r8.<init>(r9)
            return r8
        L74:
            return r9
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.shared.repository.j.a(com.quizlet.shared.models.api.keys.b, kotlin.coroutines.jvm.internal.c):java.io.Serializable");
    }
}

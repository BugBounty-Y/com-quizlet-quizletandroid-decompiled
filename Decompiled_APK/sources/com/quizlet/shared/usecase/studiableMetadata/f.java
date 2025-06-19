package com.quizlet.shared.usecase.studiableMetadata;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class f implements h {
    public final com.quizlet.shared.repository.c a;

    public f(com.quizlet.shared.repository.c repository) {
        Intrinsics.checkNotNullParameter(repository, "repository");
        this.a = repository;
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object a(long r5, assistantMode.enums.s r7, java.lang.Boolean r8, kotlin.coroutines.jvm.internal.c r9) {
        /*
            r4 = this;
            boolean r0 = r9 instanceof com.quizlet.shared.usecase.studiableMetadata.e
            if (r0 == 0) goto L13
            r0 = r9
            com.quizlet.shared.usecase.studiableMetadata.e r0 = (com.quizlet.shared.usecase.studiableMetadata.e) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L18
        L13:
            com.quizlet.shared.usecase.studiableMetadata.e r0 = new com.quizlet.shared.usecase.studiableMetadata.e
            r0.<init>(r4, r9)
        L18:
            java.lang.Object r9 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 1
            if (r2 == 0) goto L2f
            if (r2 != r3) goto L27
            androidx.glance.appwidget.protobuf.Z.e(r9)
            goto L46
        L27:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L2f:
            androidx.glance.appwidget.protobuf.Z.e(r9)
            com.quizlet.shared.models.api.keys.b r9 = new com.quizlet.shared.models.api.keys.b
            assistantMode.refactored.enums.StudiableContainerType$Companion r2 = assistantMode.refactored.enums.j.Companion
            r9.<init>(r5, r7, r8)
            r0.l = r3
            com.quizlet.shared.repository.c r5 = r4.a
            com.quizlet.shared.repository.j r5 = (com.quizlet.shared.repository.j) r5
            java.lang.Object r9 = com.quizlet.shared.repository.j.b(r5, r9, r0)
            if (r9 != r1) goto L46
            return r1
        L46:
            kotlin.r r9 = (kotlin.r) r9
            r5 = 0
            if (r9 == 0) goto L55
            java.lang.Object r6 = r9.a
            boolean r7 = r6 instanceof kotlin.q
            if (r7 == 0) goto L52
            goto L53
        L52:
            r5 = r6
        L53:
            assistantMode.refactored.types.StudiableMetadataContent r5 = (assistantMode.refactored.types.StudiableMetadataContent) r5
        L55:
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.shared.usecase.studiableMetadata.f.a(long, assistantMode.enums.s, java.lang.Boolean, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }
}

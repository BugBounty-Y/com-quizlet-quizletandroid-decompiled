package com.quizlet.shared.usecase.studiableMetadata;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class d implements g {
    public final h a;

    public d(h getStudiableMetadataForSetUseCase) {
        Intrinsics.checkNotNullParameter(getStudiableMetadataForSetUseCase, "getStudiableMetadataForSetUseCase");
        this.a = getStudiableMetadataForSetUseCase;
    }

    /* JADX WARN: Removed duplicated region for block: B:8:0x0014  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object a(assistantMode.enums.s r8, long r9, kotlin.coroutines.jvm.internal.c r11) {
        /*
            r7 = this;
            boolean r0 = r11 instanceof com.quizlet.shared.usecase.studiableMetadata.b
            if (r0 == 0) goto L14
            r0 = r11
            com.quizlet.shared.usecase.studiableMetadata.b r0 = (com.quizlet.shared.usecase.studiableMetadata.b) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L14
            int r1 = r1 - r2
            r0.l = r1
        L12:
            r6 = r0
            goto L1a
        L14:
            com.quizlet.shared.usecase.studiableMetadata.b r0 = new com.quizlet.shared.usecase.studiableMetadata.b
            r0.<init>(r7, r11)
            goto L12
        L1a:
            java.lang.Object r11 = r6.j
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r6.l
            r2 = 1
            if (r1 == 0) goto L31
            if (r1 != r2) goto L29
            androidx.glance.appwidget.protobuf.Z.e(r11)
            goto L46
        L29:
            java.lang.IllegalStateException r8 = new java.lang.IllegalStateException
            java.lang.String r9 = "call to 'resume' before 'invoke' with coroutine"
            r8.<init>(r9)
            throw r8
        L31:
            androidx.glance.appwidget.protobuf.Z.e(r11)
            java.lang.Boolean r5 = java.lang.Boolean.FALSE
            r6.l = r2
            com.quizlet.shared.usecase.studiableMetadata.h r11 = r7.a
            r1 = r11
            com.quizlet.shared.usecase.studiableMetadata.f r1 = (com.quizlet.shared.usecase.studiableMetadata.f) r1
            r4 = r8
            r2 = r9
            java.lang.Object r11 = r1.a(r2, r4, r5, r6)
            if (r11 != r0) goto L46
            return r0
        L46:
            assistantMode.refactored.types.StudiableMetadataContent r11 = (assistantMode.refactored.types.StudiableMetadataContent) r11
            if (r11 != 0) goto L54
            assistantMode.refactored.types.StudiableMetadataContent r8 = new assistantMode.refactored.types.StudiableMetadataContent
            kotlin.collections.K r9 = kotlin.collections.K.a
            assistantMode.enums.q r10 = assistantMode.enums.q.b
            r8.<init>(r9, r10)
            return r8
        L54:
            return r11
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.shared.usecase.studiableMetadata.d.a(assistantMode.enums.s, long, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }
}

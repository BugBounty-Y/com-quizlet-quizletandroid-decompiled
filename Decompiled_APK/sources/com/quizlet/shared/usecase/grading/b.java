package com.quizlet.shared.usecase.grading;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class b implements c {
    public final com.quizlet.shared.repository.a a;

    public b(com.quizlet.shared.repository.a repository) {
        Intrinsics.checkNotNullParameter(repository, "repository");
        this.a = repository;
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object a(java.lang.String r5, java.lang.String r6, java.lang.String r7, kotlin.coroutines.jvm.internal.c r8) {
        /*
            r4 = this;
            boolean r0 = r8 instanceof com.quizlet.shared.usecase.grading.a
            if (r0 == 0) goto L13
            r0 = r8
            com.quizlet.shared.usecase.grading.a r0 = (com.quizlet.shared.usecase.grading.a) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L18
        L13:
            com.quizlet.shared.usecase.grading.a r0 = new com.quizlet.shared.usecase.grading.a
            r0.<init>(r4, r8)
        L18:
            java.lang.Object r8 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 1
            if (r2 == 0) goto L2f
            if (r2 != r3) goto L27
            androidx.glance.appwidget.protobuf.Z.e(r8)
            goto L48
        L27:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L2f:
            androidx.glance.appwidget.protobuf.Z.e(r8)
            com.quizlet.shared.models.api.keys.a r8 = new com.quizlet.shared.models.api.keys.a
            r8.<init>(r5, r6, r7)
            r0.l = r3
            com.quizlet.shared.repository.a r5 = r4.a
            androidx.compose.animation.core.J0 r5 = (androidx.compose.animation.core.J0) r5
            java.lang.Object r5 = r5.b
            com.quizlet.shared.quizletapi.base.e r5 = (com.quizlet.shared.quizletapi.base.e) r5
            java.lang.Object r8 = r5.a(r8, r0)
            if (r8 != r1) goto L48
            return r1
        L48:
            kotlin.r r8 = (kotlin.r) r8
            if (r8 == 0) goto L54
            java.lang.Object r5 = r8.a
            androidx.glance.appwidget.protobuf.Z.e(r5)
            com.quizlet.shared.models.api.grading.LongtextGradingResult r5 = (com.quizlet.shared.models.api.grading.LongtextGradingResult) r5
            return r5
        L54:
            r5 = 0
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.shared.usecase.grading.b.a(java.lang.String, java.lang.String, java.lang.String, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }
}

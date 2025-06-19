package com.quizlet.shared.usecase.eligibility;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class b implements c {
    public final com.quizlet.shared.repository.eligibility.a a;

    public b(com.quizlet.shared.repository.eligibility.a usersFeatureEligibilityRepository) {
        Intrinsics.checkNotNullParameter(usersFeatureEligibilityRepository, "usersFeatureEligibilityRepository");
        this.a = usersFeatureEligibilityRepository;
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.io.Serializable a(java.util.ArrayList r5, kotlin.coroutines.jvm.internal.c r6) {
        /*
            r4 = this;
            boolean r0 = r6 instanceof com.quizlet.shared.usecase.eligibility.a
            if (r0 == 0) goto L13
            r0 = r6
            com.quizlet.shared.usecase.eligibility.a r0 = (com.quizlet.shared.usecase.eligibility.a) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            com.quizlet.shared.usecase.eligibility.a r0 = new com.quizlet.shared.usecase.eligibility.a
            r0.<init>(r4, r6)
        L18:
            java.lang.Object r6 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 1
            if (r2 == 0) goto L31
            if (r2 != r3) goto L29
            java.util.List r5 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r6)
            goto L47
        L29:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L31:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            r0.j = r5
            r0.m = r3
            com.quizlet.shared.repository.eligibility.a r6 = r4.a
            com.quizlet.shared.repository.eligibility.b r6 = (com.quizlet.shared.repository.eligibility.b) r6
            com.quizlet.shared.quizletapi.eligibility.a r6 = r6.a
            com.quizlet.shared.quizletapi.eligibility.d r6 = (com.quizlet.shared.quizletapi.eligibility.d) r6
            java.io.Serializable r6 = r6.a(r5, r0)
            if (r6 != r1) goto L47
            return r1
        L47:
            kotlin.r r6 = (kotlin.r) r6
            if (r6 == 0) goto L53
            java.lang.Object r6 = r6.a
            androidx.glance.appwidget.protobuf.Z.e(r6)
            java.util.List r6 = (java.util.List) r6
            goto L54
        L53:
            r6 = 0
        L54:
            java.util.LinkedHashMap r0 = new java.util.LinkedHashMap
            r1 = 10
            int r1 = kotlin.collections.C.q(r5, r1)
            int r1 = kotlin.collections.U.a(r1)
            r2 = 16
            if (r1 >= r2) goto L65
            r1 = r2
        L65:
            r0.<init>(r1)
            java.util.Iterator r5 = r5.iterator()
        L6c:
            boolean r1 = r5.hasNext()
            if (r1 == 0) goto L89
            java.lang.Object r1 = r5.next()
            r2 = r1
            java.lang.String r2 = (java.lang.String) r2
            if (r6 == 0) goto L80
            boolean r2 = r6.contains(r2)
            goto L81
        L80:
            r2 = 0
        L81:
            java.lang.Boolean r2 = java.lang.Boolean.valueOf(r2)
            r0.put(r1, r2)
            goto L6c
        L89:
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.shared.usecase.eligibility.b.a(java.util.ArrayList, kotlin.coroutines.jvm.internal.c):java.io.Serializable");
    }
}

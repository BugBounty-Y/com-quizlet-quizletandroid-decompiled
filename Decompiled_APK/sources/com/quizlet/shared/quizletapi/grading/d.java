package com.quizlet.shared.quizletapi.grading;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class d implements a {
    public final com.quizlet.remote.kmp.a a;
    public final kotlinx.serialization.json.c b;
    public final String c;

    public d(com.quizlet.remote.kmp.a httpClient, kotlinx.serialization.json.c json, com.quizlet.shared.quizletapi.b quizletApi) {
        Intrinsics.checkNotNullParameter(httpClient, "httpClient");
        Intrinsics.checkNotNullParameter(json, "json");
        Intrinsics.checkNotNullParameter(quizletApi, "quizletApi");
        this.a = httpClient;
        this.b = json;
        this.c = com.quizlet.shared.quizletapi.b.a(quizletApi, "grading", "grade-longtext-answer", 12);
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    @Override // com.quizlet.shared.quizletapi.base.e
    /* renamed from: b, reason: merged with bridge method [inline-methods] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.io.Serializable a(com.quizlet.shared.models.api.keys.a r8, kotlin.coroutines.jvm.internal.c r9) {
        /*
            r7 = this;
            boolean r0 = r9 instanceof com.quizlet.shared.quizletapi.grading.b
            if (r0 == 0) goto L13
            r0 = r9
            com.quizlet.shared.quizletapi.grading.b r0 = (com.quizlet.shared.quizletapi.grading.b) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            com.quizlet.shared.quizletapi.grading.b r0 = new com.quizlet.shared.quizletapi.grading.b
            r0.<init>(r7, r9)
        L18:
            java.lang.Object r9 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 1
            if (r2 == 0) goto L31
            if (r2 != r3) goto L29
            com.quizlet.shared.httpclient.e r8 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r9)
            goto L73
        L29:
            java.lang.IllegalStateException r8 = new java.lang.IllegalStateException
            java.lang.String r9 = "call to 'resume' before 'invoke' with coroutine"
            r8.<init>(r9)
            throw r8
        L31:
            androidx.glance.appwidget.protobuf.Z.e(r9)
            java.lang.String r9 = r8.b
            kotlin.Pair r2 = new kotlin.Pair
            java.lang.String r4 = "expectedAnswer"
            r2.<init>(r4, r9)
            kotlin.Pair r9 = new kotlin.Pair
            java.lang.String r4 = "submittedAnswer"
            java.lang.String r5 = r8.a
            r9.<init>(r4, r5)
            kotlin.Pair r4 = new kotlin.Pair
            java.lang.String r5 = "languageCode"
            java.lang.String r8 = r8.c
            r4.<init>(r5, r8)
            kotlin.Pair[] r8 = new kotlin.Pair[]{r2, r9, r4}
            java.util.Map r8 = kotlin.collections.V.f(r8)
            com.quizlet.shared.httpclient.e r9 = new com.quizlet.shared.httpclient.e
            com.quizlet.shared.httpclient.d r2 = com.quizlet.shared.httpclient.d.b
            java.lang.String r4 = r7.c
            r5 = 0
            r9.<init>(r4, r8, r5, r2)
            r0.j = r9
            r0.m = r3
            com.quizlet.remote.kmp.a r8 = r7.a
            kotlinx.serialization.json.c r2 = r7.b
            java.lang.Object r8 = com.quizlet.shared.quizletapi.utils.c.a(r8, r9, r2, r0)
            if (r8 != r1) goto L70
            return r1
        L70:
            r6 = r9
            r9 = r8
            r8 = r6
        L73:
            com.quizlet.shared.models.api.base.QuizletApiWrapper r9 = (com.quizlet.shared.models.api.base.QuizletApiWrapper) r9
            com.quizlet.shared.quizletapi.grading.c r0 = com.quizlet.shared.quizletapi.grading.c.a
            java.lang.Object r8 = com.google.android.gms.internal.mlkit_vision_barcode.U4.d(r9, r8, r0)
            kotlin.r r9 = new kotlin.r
            r9.<init>(r8)
            return r9
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.shared.quizletapi.grading.d.a(com.quizlet.shared.models.api.keys.a, kotlin.coroutines.jvm.internal.c):java.io.Serializable");
    }
}

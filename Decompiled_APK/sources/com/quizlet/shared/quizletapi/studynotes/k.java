package com.quizlet.shared.quizletapi.studynotes;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class k implements f {
    public final com.quizlet.remote.kmp.a a;
    public final kotlinx.serialization.json.c b;
    public final com.quizlet.shared.quizletapi.b c;

    public k(com.quizlet.remote.kmp.a httpClient, kotlinx.serialization.json.c json, com.quizlet.shared.quizletapi.b quizletApi) {
        Intrinsics.checkNotNullParameter(httpClient, "httpClient");
        Intrinsics.checkNotNullParameter(json, "json");
        Intrinsics.checkNotNullParameter(quizletApi, "quizletApi");
        this.a = httpClient;
        this.b = json;
        this.c = quizletApi;
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    @Override // com.quizlet.shared.quizletapi.base.e
    /* renamed from: b, reason: merged with bridge method [inline-methods] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.io.Serializable a(com.quizlet.shared.models.api.notes.d r11, kotlin.coroutines.jvm.internal.c r12) {
        /*
            r10 = this;
            boolean r0 = r12 instanceof com.quizlet.shared.quizletapi.studynotes.j
            if (r0 == 0) goto L13
            r0 = r12
            com.quizlet.shared.quizletapi.studynotes.j r0 = (com.quizlet.shared.quizletapi.studynotes.j) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            com.quizlet.shared.quizletapi.studynotes.j r0 = new com.quizlet.shared.quizletapi.studynotes.j
            r0.<init>(r10, r12)
        L18:
            java.lang.Object r12 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 1
            if (r2 == 0) goto L31
            if (r2 != r3) goto L29
            com.quizlet.shared.httpclient.e r11 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r12)
            goto L5a
        L29:
            java.lang.IllegalStateException r11 = new java.lang.IllegalStateException
            java.lang.String r12 = "call to 'resume' before 'invoke' with coroutine"
            r11.<init>(r12)
            throw r11
        L31:
            androidx.glance.appwidget.protobuf.Z.e(r12)
            com.quizlet.shared.httpclient.e r4 = new com.quizlet.shared.httpclient.e
            java.lang.String r11 = r11.a
            com.quizlet.shared.quizletapi.b r12 = r10.c
            java.lang.String r2 = "artifacts"
            r5 = 12
            java.lang.String r5 = com.quizlet.shared.quizletapi.b.a(r12, r2, r11, r5)
            com.quizlet.shared.httpclient.d r8 = com.quizlet.shared.httpclient.d.a
            r7 = 0
            r9 = 6
            r6 = 0
            r4.<init>(r5, r6, r7, r8, r9)
            r0.j = r4
            r0.m = r3
            com.quizlet.remote.kmp.a r11 = r10.a
            kotlinx.serialization.json.c r12 = r10.b
            java.lang.Object r12 = com.quizlet.shared.quizletapi.utils.c.a(r11, r4, r12, r0)
            if (r12 != r1) goto L59
            return r1
        L59:
            r11 = r4
        L5a:
            com.quizlet.shared.models.api.base.QuizletApiWrapper r12 = (com.quizlet.shared.models.api.base.QuizletApiWrapper) r12
            com.quizlet.shared.quizletapi.studynotes.b r0 = com.quizlet.shared.quizletapi.studynotes.b.d
            java.lang.Object r11 = com.google.android.gms.internal.mlkit_vision_barcode.U4.d(r12, r11, r0)
            kotlin.r r12 = new kotlin.r
            r12.<init>(r11)
            return r12
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.shared.quizletapi.studynotes.k.a(com.quizlet.shared.models.api.notes.d, kotlin.coroutines.jvm.internal.c):java.io.Serializable");
    }
}

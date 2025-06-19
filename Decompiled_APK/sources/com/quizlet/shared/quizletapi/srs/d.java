package com.quizlet.shared.quizletapi.srs;

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
        this.c = com.quizlet.shared.quizletapi.b.a(quizletApi, "srs", "status", 12);
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    @Override // com.quizlet.shared.quizletapi.base.e
    /* renamed from: b, reason: merged with bridge method [inline-methods] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.io.Serializable a(com.quizlet.shared.models.api.srs.SrsRequest r11, kotlin.coroutines.jvm.internal.c r12) {
        /*
            r10 = this;
            boolean r0 = r12 instanceof com.quizlet.shared.quizletapi.srs.b
            if (r0 == 0) goto L13
            r0 = r12
            com.quizlet.shared.quizletapi.srs.b r0 = (com.quizlet.shared.quizletapi.srs.b) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            com.quizlet.shared.quizletapi.srs.b r0 = new com.quizlet.shared.quizletapi.srs.b
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
            goto L6f
        L29:
            java.lang.IllegalStateException r11 = new java.lang.IllegalStateException
            java.lang.String r12 = "call to 'resume' before 'invoke' with coroutine"
            r11.<init>(r12)
            throw r11
        L31:
            androidx.glance.appwidget.protobuf.Z.e(r12)
            com.quizlet.shared.httpclient.e r4 = new com.quizlet.shared.httpclient.e
            kotlin.jvm.internal.N r12 = kotlin.jvm.internal.N.a
            com.google.android.gms.internal.mlkit_vision_camera.R1.g(r12)
            kotlinx.serialization.internal.q0 r12 = kotlinx.serialization.internal.q0.a
            com.quizlet.shared.models.api.srs.SrsRequest$Companion r12 = com.quizlet.shared.models.api.srs.SrsRequest.Companion
            kotlinx.serialization.KSerializer r12 = r12.serializer()
            kotlinx.serialization.internal.F r12 = com.google.android.gms.internal.mlkit_vision_camera.R1.b(r12)
            kotlin.Pair r2 = new kotlin.Pair
            java.lang.String r5 = "srs"
            r2.<init>(r5, r11)
            java.util.Map r11 = kotlin.collections.U.b(r2)
            kotlinx.serialization.json.c r2 = r10.b
            java.lang.String r7 = r2.c(r12, r11)
            com.quizlet.shared.httpclient.d r8 = com.quizlet.shared.httpclient.d.b
            r6 = 0
            r9 = 2
            java.lang.String r5 = r10.c
            r4.<init>(r5, r6, r7, r8, r9)
            r0.j = r4
            r0.m = r3
            com.quizlet.remote.kmp.a r11 = r10.a
            java.lang.Object r12 = com.quizlet.shared.quizletapi.utils.c.a(r11, r4, r2, r0)
            if (r12 != r1) goto L6e
            return r1
        L6e:
            r11 = r4
        L6f:
            com.quizlet.shared.models.api.base.QuizletApiWrapper r12 = (com.quizlet.shared.models.api.base.QuizletApiWrapper) r12
            com.quizlet.shared.quizletapi.srs.c r0 = com.quizlet.shared.quizletapi.srs.c.a
            java.lang.Object r11 = com.google.android.gms.internal.mlkit_vision_barcode.U4.d(r12, r11, r0)
            kotlin.r r12 = new kotlin.r
            r12.<init>(r11)
            return r12
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.shared.quizletapi.srs.d.a(com.quizlet.shared.models.api.srs.SrsRequest, kotlin.coroutines.jvm.internal.c):java.io.Serializable");
    }
}

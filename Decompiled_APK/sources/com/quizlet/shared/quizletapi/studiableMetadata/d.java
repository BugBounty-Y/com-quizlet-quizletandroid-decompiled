package com.quizlet.shared.quizletapi.studiableMetadata;

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
        this.c = com.quizlet.shared.quizletapi.b.a(quizletApi, "studiable-metadata", null, 14);
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    @Override // com.quizlet.shared.quizletapi.base.e
    /* renamed from: b, reason: merged with bridge method [inline-methods] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.io.Serializable a(com.quizlet.shared.models.api.keys.b r9, kotlin.coroutines.jvm.internal.c r10) {
        /*
            r8 = this;
            boolean r0 = r10 instanceof com.quizlet.shared.quizletapi.studiableMetadata.b
            if (r0 == 0) goto L13
            r0 = r10
            com.quizlet.shared.quizletapi.studiableMetadata.b r0 = (com.quizlet.shared.quizletapi.studiableMetadata.b) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            com.quizlet.shared.quizletapi.studiableMetadata.b r0 = new com.quizlet.shared.quizletapi.studiableMetadata.b
            r0.<init>(r8, r10)
        L18:
            java.lang.Object r10 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 1
            if (r2 == 0) goto L31
            if (r2 != r3) goto L29
            com.quizlet.shared.httpclient.e r9 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r10)
            goto L8e
        L29:
            java.lang.IllegalStateException r9 = new java.lang.IllegalStateException
            java.lang.String r10 = "call to 'resume' before 'invoke' with coroutine"
            r9.<init>(r10)
            throw r9
        L31:
            androidx.glance.appwidget.protobuf.Z.e(r10)
            long r4 = r9.a
            java.lang.String r10 = java.lang.String.valueOf(r4)
            kotlin.Pair r2 = new kotlin.Pair
            java.lang.String r4 = "filters[studiableContainerId]"
            r2.<init>(r4, r10)
            assistantMode.refactored.enums.StudiableContainerType$Companion r10 = assistantMode.refactored.enums.j.Companion
            java.lang.String r10 = java.lang.String.valueOf(r3)
            kotlin.Pair r4 = new kotlin.Pair
            java.lang.String r5 = "filters[studiableContainerType]"
            r4.<init>(r5, r10)
            assistantMode.enums.s r10 = r9.b
            int r10 = r10.a
            java.lang.String r10 = java.lang.String.valueOf(r10)
            kotlin.Pair r5 = new kotlin.Pair
            java.lang.String r6 = "filters[studiableMetadataType]"
            r5.<init>(r6, r10)
            java.lang.Boolean r9 = r9.c
            java.lang.String r9 = java.lang.String.valueOf(r9)
            kotlin.Pair r10 = new kotlin.Pair
            java.lang.String r6 = "filters[isPolling]"
            r10.<init>(r6, r9)
            kotlin.Pair[] r9 = new kotlin.Pair[]{r2, r4, r5, r10}
            java.util.Map r9 = kotlin.collections.V.f(r9)
            com.quizlet.shared.httpclient.e r10 = new com.quizlet.shared.httpclient.e
            com.quizlet.shared.httpclient.d r2 = com.quizlet.shared.httpclient.d.a
            r4 = 0
            java.lang.String r5 = r8.c
            r10.<init>(r5, r9, r4, r2)
            r0.j = r10
            r0.m = r3
            com.quizlet.remote.kmp.a r9 = r8.a
            kotlinx.serialization.json.c r2 = r8.b
            java.lang.Object r9 = com.quizlet.shared.quizletapi.utils.c.a(r9, r10, r2, r0)
            if (r9 != r1) goto L8b
            return r1
        L8b:
            r7 = r10
            r10 = r9
            r9 = r7
        L8e:
            com.quizlet.shared.models.api.base.QuizletApiWrapper r10 = (com.quizlet.shared.models.api.base.QuizletApiWrapper) r10
            com.quizlet.shared.quizletapi.studiableMetadata.c r0 = com.quizlet.shared.quizletapi.studiableMetadata.c.a
            java.lang.Object r9 = com.google.android.gms.internal.mlkit_vision_barcode.U4.d(r10, r9, r0)
            kotlin.r r10 = new kotlin.r
            r10.<init>(r9)
            return r10
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.shared.quizletapi.studiableMetadata.d.a(com.quizlet.shared.models.api.keys.b, kotlin.coroutines.jvm.internal.c):java.io.Serializable");
    }
}

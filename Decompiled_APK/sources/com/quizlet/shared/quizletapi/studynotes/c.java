package com.quizlet.shared.quizletapi.studynotes;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class c implements d {
    public final com.quizlet.remote.kmp.a a;
    public final kotlinx.serialization.json.c b;
    public final String c;
    public final String d;

    public c(com.quizlet.remote.kmp.a httpClient, kotlinx.serialization.json.c json, com.quizlet.shared.quizletapi.b quizletApi) {
        Intrinsics.checkNotNullParameter(httpClient, "httpClient");
        Intrinsics.checkNotNullParameter(json, "json");
        Intrinsics.checkNotNullParameter(quizletApi, "quizletApi");
        this.a = httpClient;
        this.b = json;
        this.c = com.quizlet.shared.quizletapi.b.a(quizletApi, "new-study-notes", "text", 12);
        this.d = com.quizlet.shared.quizletapi.b.a(quizletApi, "new-study-notes", "file", 12);
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    @Override // com.quizlet.shared.quizletapi.base.e
    /* renamed from: b, reason: merged with bridge method [inline-methods] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.io.Serializable a(com.quizlet.shared.models.api.notes.b r8, kotlin.coroutines.jvm.internal.c r9) {
        /*
            r7 = this;
            boolean r0 = r9 instanceof com.quizlet.shared.quizletapi.studynotes.a
            if (r0 == 0) goto L13
            r0 = r9
            com.quizlet.shared.quizletapi.studynotes.a r0 = (com.quizlet.shared.quizletapi.studynotes.a) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            com.quizlet.shared.quizletapi.studynotes.a r0 = new com.quizlet.shared.quizletapi.studynotes.a
            r0.<init>(r7, r9)
        L18:
            java.lang.Object r9 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 1
            if (r2 == 0) goto L31
            if (r2 != r3) goto L29
            com.google.android.gms.internal.mlkit_vision_barcode.R4 r8 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r9)
            goto L8c
        L29:
            java.lang.IllegalStateException r8 = new java.lang.IllegalStateException
            java.lang.String r9 = "call to 'resume' before 'invoke' with coroutine"
            r8.<init>(r9)
            throw r8
        L31:
            androidx.glance.appwidget.protobuf.Z.e(r9)
            boolean r9 = r8 instanceof com.quizlet.shared.models.api.notes.CreateStudyNotesRequest$Text
            kotlinx.serialization.json.c r2 = r7.b
            if (r9 == 0) goto L5e
            com.quizlet.shared.models.api.notes.CreateStudyNotesRequest$Text$Companion r9 = com.quizlet.shared.models.api.notes.CreateStudyNotesRequest$Text.Companion
            kotlinx.serialization.KSerializer r9 = r9.serializer()
            java.lang.String r9 = r2.c(r9, r8)
            com.quizlet.shared.httpclient.d r4 = com.quizlet.shared.httpclient.d.b
            com.quizlet.shared.models.api.notes.CreateStudyNotesRequest$Text r8 = (com.quizlet.shared.models.api.notes.CreateStudyNotesRequest$Text) r8
            java.lang.String r8 = r8.c
            kotlin.Pair r5 = new kotlin.Pair
            java.lang.String r6 = "inputType"
            r5.<init>(r6, r8)
            java.util.Map r8 = kotlin.collections.U.b(r5)
            com.quizlet.shared.httpclient.e r5 = new com.quizlet.shared.httpclient.e
            java.lang.String r6 = r7.c
            r5.<init>(r6, r8, r9, r4)
            r8 = r5
            goto L7f
        L5e:
            boolean r9 = r8 instanceof com.quizlet.shared.models.api.notes.a
            if (r9 == 0) goto L9a
            com.quizlet.shared.httpclient.c r9 = new com.quizlet.shared.httpclient.c
            com.quizlet.shared.models.api.notes.a r8 = (com.quizlet.shared.models.api.notes.a) r8
            boolean r4 = r8.b
            java.lang.String r4 = java.lang.String.valueOf(r4)
            kotlin.Pair r5 = new kotlin.Pair
            java.lang.String r6 = "private"
            r5.<init>(r6, r4)
            java.util.Map r4 = kotlin.collections.U.b(r5)
            java.util.ArrayList r8 = r8.a
            java.lang.String r5 = r7.d
            r9.<init>(r5, r4, r8)
            r8 = r9
        L7f:
            r0.j = r8
            r0.m = r3
            com.quizlet.remote.kmp.a r9 = r7.a
            java.lang.Object r9 = com.quizlet.shared.quizletapi.utils.c.a(r9, r8, r2, r0)
            if (r9 != r1) goto L8c
            return r1
        L8c:
            com.quizlet.shared.models.api.base.QuizletApiWrapper r9 = (com.quizlet.shared.models.api.base.QuizletApiWrapper) r9
            com.quizlet.shared.quizletapi.studynotes.b r0 = com.quizlet.shared.quizletapi.studynotes.b.b
            java.lang.Object r8 = com.google.android.gms.internal.mlkit_vision_barcode.U4.d(r9, r8, r0)
            kotlin.r r9 = new kotlin.r
            r9.<init>(r8)
            return r9
        L9a:
            kotlin.NoWhenBranchMatchedException r8 = new kotlin.NoWhenBranchMatchedException
            r8.<init>()
            throw r8
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.shared.quizletapi.studynotes.c.a(com.quizlet.shared.models.api.notes.b, kotlin.coroutines.jvm.internal.c):java.io.Serializable");
    }
}

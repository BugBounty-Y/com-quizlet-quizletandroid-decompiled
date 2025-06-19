package com.quizlet.shared.quizletapi.base;

import com.quizlet.shared.models.api.base.QuizletApiThreeResponse;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public abstract class c implements e, d {
    public final com.quizlet.remote.kmp.a a;
    public final kotlinx.serialization.json.c b;

    public c(com.quizlet.remote.kmp.a httpClient, kotlinx.serialization.json.c json) {
        Intrinsics.checkNotNullParameter(httpClient, "httpClient");
        Intrinsics.checkNotNullParameter(json, "json");
        this.a = httpClient;
        this.b = json;
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static java.lang.Object c(com.quizlet.shared.quizletapi.base.c r4, java.lang.Object r5, kotlin.coroutines.jvm.internal.c r6) {
        /*
            boolean r0 = r6 instanceof com.quizlet.shared.quizletapi.base.a
            if (r0 == 0) goto L13
            r0 = r6
            com.quizlet.shared.quizletapi.base.a r0 = (com.quizlet.shared.quizletapi.base.a) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L18
        L13:
            com.quizlet.shared.quizletapi.base.a r0 = new com.quizlet.shared.quizletapi.base.a
            r0.<init>(r4, r6)
        L18:
            java.lang.Object r6 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 1
            if (r2 == 0) goto L33
            if (r2 != r3) goto L2b
            androidx.glance.appwidget.protobuf.Z.e(r6)
            kotlin.r r6 = (kotlin.r) r6
            java.lang.Object r4 = r6.a
            goto L42
        L2b:
            java.lang.IllegalStateException r4 = new java.lang.IllegalStateException
            java.lang.String r5 = "call to 'resume' before 'invoke' with coroutine"
            r4.<init>(r5)
            throw r4
        L33:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            r0.l = r3
            r4.getClass()
            java.io.Serializable r4 = d(r4, r5, r0)
            if (r4 != r1) goto L42
            return r1
        L42:
            kotlin.p r5 = kotlin.r.b
            boolean r5 = r4 instanceof kotlin.q
            if (r5 != 0) goto L58
            java.util.List r4 = (java.util.List) r4
            java.lang.Object r4 = kotlin.collections.CollectionsKt.L(r4)
            kotlin.r r4 = (kotlin.r) r4
            java.lang.Object r4 = r4.a
            kotlin.r r5 = new kotlin.r
            r5.<init>(r4)
            r4 = r5
        L58:
            java.lang.Throwable r5 = kotlin.r.a(r4)
            if (r5 != 0) goto L5f
            return r4
        L5f:
            kotlin.q r4 = androidx.glance.appwidget.protobuf.Z.b(r5)
            kotlin.r r5 = new kotlin.r
            r5.<init>(r4)
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.shared.quizletapi.base.c.c(com.quizlet.shared.quizletapi.base.c, java.lang.Object, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static java.io.Serializable d(com.quizlet.shared.quizletapi.base.c r12, java.lang.Object r13, kotlin.coroutines.jvm.internal.c r14) {
        /*
            boolean r0 = r14 instanceof com.quizlet.shared.quizletapi.base.b
            if (r0 == 0) goto L13
            r0 = r14
            com.quizlet.shared.quizletapi.base.b r0 = (com.quizlet.shared.quizletapi.base.b) r0
            int r1 = r0.n
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.n = r1
            goto L18
        L13:
            com.quizlet.shared.quizletapi.base.b r0 = new com.quizlet.shared.quizletapi.base.b
            r0.<init>(r12, r14)
        L18:
            java.lang.Object r14 = r0.l
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.n
            r3 = 1
            if (r2 == 0) goto L34
            if (r2 != r3) goto L2c
            com.google.android.gms.internal.mlkit_vision_barcode.R4 r12 = r0.k
            com.quizlet.shared.quizletapi.base.c r13 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r14)
            r6 = r13
            goto L4e
        L2c:
            java.lang.IllegalStateException r12 = new java.lang.IllegalStateException
            java.lang.String r13 = "call to 'resume' before 'invoke' with coroutine"
            r12.<init>(r13)
            throw r12
        L34:
            androidx.glance.appwidget.protobuf.Z.e(r14)
            com.quizlet.shared.httpclient.e r13 = r12.b(r13)
            r0.j = r12
            r0.k = r13
            r0.n = r3
            com.quizlet.remote.kmp.a r14 = r12.a
            kotlinx.serialization.json.c r2 = r12.b
            java.lang.Object r14 = com.quizlet.shared.quizletapi.utils.c.a(r14, r13, r2, r0)
            if (r14 != r1) goto L4c
            return r1
        L4c:
            r6 = r12
            r12 = r13
        L4e:
            com.quizlet.shared.models.api.base.QuizletApiWrapper r14 = (com.quizlet.shared.models.api.base.QuizletApiWrapper) r14
            com.quizlet.search.composables.E r4 = new com.quizlet.search.composables.E
            java.lang.Class<com.quizlet.shared.quizletapi.base.c> r7 = com.quizlet.shared.quizletapi.base.c.class
            java.lang.String r8 = "transform"
            r5 = 1
            java.lang.String r9 = "transform(Lcom/quizlet/shared/models/api/base/QuizletApiThreeResponse;)Ljava/lang/Object;"
            r10 = 0
            r11 = 1
            r4.<init>(r5, r6, r7, r8, r9, r10, r11)
            java.lang.String r13 = "request"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r12, r13)
            java.lang.String r0 = "getDataFromResponse"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r4, r0)
            r1 = 0
            if (r14 == 0) goto L6e
            java.util.List r2 = r14.a
            goto L6f
        L6e:
            r2 = r1
        L6f:
            if (r2 == 0) goto L7b
            boolean r5 = r2.isEmpty()
            r3 = r3 ^ r5
            java.lang.Boolean r3 = java.lang.Boolean.valueOf(r3)
            goto L7c
        L7b:
            r3 = r1
        L7c:
            java.lang.Boolean r5 = java.lang.Boolean.TRUE
            boolean r3 = kotlin.jvm.internal.Intrinsics.b(r3, r5)
            if (r3 == 0) goto Lc5
            kotlin.p r14 = kotlin.r.b
            java.util.ArrayList r14 = new java.util.ArrayList
            r1 = 10
            int r1 = kotlin.collections.C.q(r2, r1)
            r14.<init>(r1)
            java.util.Iterator r1 = r2.iterator()
        L95:
            boolean r2 = r1.hasNext()
            if (r2 == 0) goto Lc4
            java.lang.Object r2 = r1.next()
            com.quizlet.shared.models.api.base.QuizletApiThreeResponse r2 = (com.quizlet.shared.models.api.base.QuizletApiThreeResponse) r2
            java.lang.String r3 = "<this>"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r2, r3)
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r12, r13)
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r4, r0)
            java.lang.Object r3 = r4.invoke(r2)
            if (r3 == 0) goto Lb5
            kotlin.p r2 = kotlin.r.b
            goto Lbb
        Lb5:
            com.quizlet.shared.models.api.base.errors.QuizletApiError r2 = r2.c
            kotlin.q r3 = com.google.android.gms.internal.mlkit_vision_barcode.U4.b(r2, r12)
        Lbb:
            kotlin.r r2 = new kotlin.r
            r2.<init>(r3)
            r14.add(r2)
            goto L95
        Lc4:
            return r14
        Lc5:
            if (r14 == 0) goto Lc9
            com.quizlet.shared.models.api.base.errors.QuizletApiError r1 = r14.b
        Lc9:
            kotlin.q r12 = com.google.android.gms.internal.mlkit_vision_barcode.U4.b(r1, r12)
            return r12
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.shared.quizletapi.base.c.d(com.quizlet.shared.quizletapi.base.c, java.lang.Object, kotlin.coroutines.jvm.internal.c):java.io.Serializable");
    }

    @Override // com.quizlet.shared.quizletapi.base.e
    public final Object a(Object obj, kotlin.coroutines.jvm.internal.c cVar) {
        return c(this, obj, cVar);
    }

    public abstract com.quizlet.shared.httpclient.e b(Object obj);

    public abstract Object e(QuizletApiThreeResponse quizletApiThreeResponse);
}

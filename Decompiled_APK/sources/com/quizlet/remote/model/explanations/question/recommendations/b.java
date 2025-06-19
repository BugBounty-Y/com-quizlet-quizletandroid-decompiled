package com.quizlet.remote.model.explanations.question.recommendations;

import androidx.work.impl.model.c;
import com.quizlet.quizletandroid.k;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class b {
    public final c a;
    public final k b;

    public b(c dataSource, k mapper) {
        Intrinsics.checkNotNullParameter(dataSource, "dataSource");
        Intrinsics.checkNotNullParameter(mapper, "mapper");
        this.a = dataSource;
        this.b = mapper;
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.io.Serializable a(java.lang.String r5, kotlin.coroutines.jvm.internal.c r6) {
        /*
            r4 = this;
            boolean r0 = r6 instanceof com.quizlet.remote.model.explanations.question.recommendations.a
            if (r0 == 0) goto L13
            r0 = r6
            com.quizlet.remote.model.explanations.question.recommendations.a r0 = (com.quizlet.remote.model.explanations.question.recommendations.a) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            com.quizlet.remote.model.explanations.question.recommendations.a r0 = new com.quizlet.remote.model.explanations.question.recommendations.a
            r0.<init>(r4, r6)
        L18:
            java.lang.Object r6 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 1
            if (r2 == 0) goto L31
            if (r2 != r3) goto L29
            com.quizlet.remote.model.explanations.question.recommendations.b r5 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r6)
            goto L42
        L29:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L31:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            r0.j = r4
            r0.m = r3
            androidx.work.impl.model.c r6 = r4.a
            java.lang.Object r6 = r6.l(r5, r0)
            if (r6 != r1) goto L41
            return r1
        L41:
            r5 = r4
        L42:
            com.quizlet.remote.model.base.ApiThreeWrapper r6 = (com.quizlet.remote.model.base.ApiThreeWrapper) r6
            com.quizlet.remote.model.base.ApiResponse r6 = r6.a()
            com.quizlet.remote.model.explanations.textbook.TextbookResponse r6 = (com.quizlet.remote.model.explanations.textbook.TextbookResponse) r6
            if (r6 == 0) goto L7a
            com.quizlet.remote.model.explanations.textbook.TextbookResponse$Models r6 = r6.d
            if (r6 == 0) goto L7a
            java.util.List r6 = r6.a
            if (r6 == 0) goto L7a
            com.quizlet.quizletandroid.k r5 = r5.b
            java.util.ArrayList r0 = new java.util.ArrayList
            r1 = 10
            int r1 = kotlin.collections.C.q(r6, r1)
            r0.<init>(r1)
            java.util.Iterator r6 = r6.iterator()
        L65:
            boolean r1 = r6.hasNext()
            if (r1 == 0) goto L79
            java.lang.Object r1 = r6.next()
            com.quizlet.remote.model.explanations.textbook.RemoteTextbook r1 = (com.quizlet.remote.model.explanations.textbook.RemoteTextbook) r1
            com.quizlet.data.model.Textbook r1 = r5.c(r1)
            r0.add(r1)
            goto L65
        L79:
            return r0
        L7a:
            kotlin.collections.K r5 = kotlin.collections.K.a
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.remote.model.explanations.question.recommendations.b.a(java.lang.String, kotlin.coroutines.jvm.internal.c):java.io.Serializable");
    }
}

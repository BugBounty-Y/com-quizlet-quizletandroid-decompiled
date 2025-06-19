package com.quizlet.features.match.studyengine;

import com.quizlet.data.repository.metering.j;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.Set;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class b implements com.quizlet.studiablemodels.grading.d {
    public final j a;
    public androidx.work.impl.model.e b;
    public Set c;
    public int d;
    public final ArrayList e;

    public b(j dataProvider) {
        Intrinsics.checkNotNullParameter(dataProvider, "dataProvider");
        this.a = dataProvider;
        this.c = new LinkedHashSet();
        this.d = -1;
        this.e = new ArrayList();
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    @Override // com.quizlet.studiablemodels.grading.d
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object a(com.quizlet.studiablemodels.grading.StudiableQuestionResponse r6, kotlin.coroutines.jvm.internal.c r7) {
        /*
            r5 = this;
            boolean r0 = r7 instanceof com.quizlet.features.match.studyengine.a
            if (r0 == 0) goto L13
            r0 = r7
            com.quizlet.features.match.studyengine.a r0 = (com.quizlet.features.match.studyengine.a) r0
            int r1 = r0.n
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.n = r1
            goto L18
        L13:
            com.quizlet.features.match.studyengine.a r0 = new com.quizlet.features.match.studyengine.a
            r0.<init>(r5, r7)
        L18:
            java.lang.Object r7 = r0.l
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.n
            r3 = 1
            if (r2 == 0) goto L33
            if (r2 != r3) goto L2b
            com.quizlet.studiablemodels.grading.MatchingGameResponse r6 = r0.k
            com.quizlet.features.match.studyengine.b r0 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto L5b
        L2b:
            java.lang.IllegalStateException r6 = new java.lang.IllegalStateException
            java.lang.String r7 = "call to 'resume' before 'invoke' with coroutine"
            r6.<init>(r7)
            throw r6
        L33:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            androidx.work.impl.model.e r7 = r5.b
            if (r7 == 0) goto La4
            boolean r2 = r6 instanceof com.quizlet.studiablemodels.grading.MatchingGameResponse
            if (r2 == 0) goto L8a
            assistantMode.types.v r2 = com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3142f5.f(r6)
            r0.j = r5
            r4 = r6
            com.quizlet.studiablemodels.grading.MatchingGameResponse r4 = (com.quizlet.studiablemodels.grading.MatchingGameResponse) r4
            r0.k = r4
            r0.n = r3
            java.lang.Object r7 = r7.c
            assistantMode.grading.c r7 = (assistantMode.grading.c) r7
            if (r7 == 0) goto L82
            assistantMode.grading.f r3 = assistantMode.grading.f.a
            java.lang.Object r7 = r7.a(r2, r3, r0)
            if (r7 != r1) goto L5a
            return r1
        L5a:
            r0 = r5
        L5b:
            assistantMode.types.GradedAnswer r7 = (assistantMode.types.GradedAnswer) r7
            java.util.ArrayList r1 = r0.e
            com.quizlet.studiablemodels.grading.StudiableQuestionGradedAnswer r7 = com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3142f5.g(r7, r1)
            boolean r1 = r7.a
            if (r1 == 0) goto L81
            java.util.Set r1 = r0.c
            com.quizlet.studiablemodels.grading.MatchingGameResponse r6 = (com.quizlet.studiablemodels.grading.MatchingGameResponse) r6
            int r2 = r6.a
            java.lang.Integer r3 = new java.lang.Integer
            r3.<init>(r2)
            r1.add(r3)
            java.util.Set r0 = r0.c
            java.lang.Integer r1 = new java.lang.Integer
            int r6 = r6.b
            r1.<init>(r6)
            r0.add(r1)
        L81:
            return r7
        L82:
            java.lang.IllegalStateException r6 = new java.lang.IllegalStateException
            java.lang.String r7 = "Generate a matching game before attempting to grade answers"
            r6.<init>(r7)
            throw r6
        L8a:
            java.lang.Class r6 = r6.getClass()
            java.lang.String r6 = r6.getSimpleName()
            java.lang.String r7 = "Invalid StudiableQuestionResponse type. Expecting (MatchingGameResponse) but was ("
            java.lang.String r0 = ")"
            java.lang.String r6 = android.support.v4.media.session.a.B(r7, r6, r0)
            java.lang.IllegalStateException r7 = new java.lang.IllegalStateException
            java.lang.String r6 = r6.toString()
            r7.<init>(r6)
            throw r7
        La4:
            java.lang.IllegalStateException r6 = new java.lang.IllegalStateException
            java.lang.String r7 = "MatchGameGenerator not initialized. Make sure to `createMatchGame` first"
            r6.<init>(r7)
            throw r6
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.match.studyengine.b.a(com.quizlet.studiablemodels.grading.StudiableQuestionResponse, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }
}

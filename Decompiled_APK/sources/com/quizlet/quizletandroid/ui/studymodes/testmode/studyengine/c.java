package com.quizlet.quizletandroid.ui.studymodes.testmode.studyengine;

import com.google.android.gms.ads.internal.client.C1608n;
import java.util.ArrayList;
import java.util.List;

/* loaded from: classes3.dex */
public final class c implements com.quizlet.studiablemodels.grading.d {
    public C1608n a;
    public List b;
    public List c;
    public int d;
    public ArrayList e;

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    @Override // com.quizlet.studiablemodels.grading.d
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object a(com.quizlet.studiablemodels.grading.StudiableQuestionResponse r7, kotlin.coroutines.jvm.internal.c r8) {
        /*
            r6 = this;
            boolean r0 = r8 instanceof com.quizlet.quizletandroid.ui.studymodes.testmode.studyengine.a
            if (r0 == 0) goto L13
            r0 = r8
            com.quizlet.quizletandroid.ui.studymodes.testmode.studyengine.a r0 = (com.quizlet.quizletandroid.ui.studymodes.testmode.studyengine.a) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            com.quizlet.quizletandroid.ui.studymodes.testmode.studyengine.a r0 = new com.quizlet.quizletandroid.ui.studymodes.testmode.studyengine.a
            r0.<init>(r6, r8)
        L18:
            java.lang.Object r8 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 0
            r4 = 1
            if (r2 == 0) goto L32
            if (r2 != r4) goto L2a
            com.quizlet.quizletandroid.ui.studymodes.testmode.studyengine.c r7 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r8)
            goto L70
        L2a:
            java.lang.IllegalStateException r7 = new java.lang.IllegalStateException
            java.lang.String r8 = "call to 'resume' before 'invoke' with coroutine"
            r7.<init>(r8)
            throw r7
        L32:
            androidx.glance.appwidget.protobuf.Z.e(r8)
            assistantMode.types.v r7 = com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3142f5.f(r7)
            java.util.ArrayList r8 = r6.e
            if (r8 == 0) goto L9b
            int r2 = r6.d
            r8.set(r2, r7)
            com.google.android.gms.ads.internal.client.n r8 = r6.a
            if (r8 == 0) goto L95
            int r2 = r6.d
            r0.j = r6
            r0.m = r4
            java.util.ArrayList r4 = r8.l()
            int r5 = r4.size()
            if (r2 >= r5) goto L81
            java.lang.Object r2 = r4.get(r2)
            assistantMode.grading.d r2 = (assistantMode.grading.d) r2
            java.lang.Object r8 = r8.a
            assistantMode.refactored.types.AssistantGradingSettings r8 = (assistantMode.refactored.types.AssistantGradingSettings) r8
            grading.core.d r8 = r8.a()
            com.google.android.gms.internal.mlkit_vision_camera.J2 r8 = r2.b(r8)
            java.lang.Object r8 = r2.a(r7, r8, r0)
            if (r8 != r1) goto L6f
            return r1
        L6f:
            r7 = r6
        L70:
            assistantMode.types.GradedAnswer r8 = (assistantMode.types.GradedAnswer) r8
            java.util.List r7 = r7.b
            if (r7 == 0) goto L7b
            com.quizlet.studiablemodels.grading.StudiableQuestionGradedAnswer r7 = com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3142f5.g(r8, r7)
            return r7
        L7b:
            java.lang.String r7 = "diagramShapes"
            kotlin.jvm.internal.Intrinsics.m(r7)
            throw r3
        L81:
            java.lang.String r7 = "Attempting to grade answer at index "
            java.lang.String r8 = ". Only "
            java.lang.String r0 = " answers expected"
            java.lang.String r7 = android.support.v4.media.session.a.j(r7, r2, r8, r0, r5)
            java.lang.IllegalStateException r8 = new java.lang.IllegalStateException
            java.lang.String r7 = r7.toString()
            r8.<init>(r7)
            throw r8
        L95:
            java.lang.String r7 = "testGenerator"
            kotlin.jvm.internal.Intrinsics.m(r7)
            throw r3
        L9b:
            java.lang.String r7 = "questionResponses"
            kotlin.jvm.internal.Intrinsics.m(r7)
            throw r3
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.quizletandroid.ui.studymodes.testmode.studyengine.c.a(com.quizlet.studiablemodels.grading.StudiableQuestionResponse, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object b(kotlin.coroutines.jvm.internal.c r8) {
        /*
            r7 = this;
            boolean r0 = r8 instanceof com.quizlet.quizletandroid.ui.studymodes.testmode.studyengine.b
            if (r0 == 0) goto L13
            r0 = r8
            com.quizlet.quizletandroid.ui.studymodes.testmode.studyengine.b r0 = (com.quizlet.quizletandroid.ui.studymodes.testmode.studyengine.b) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            com.quizlet.quizletandroid.ui.studymodes.testmode.studyengine.b r0 = new com.quizlet.quizletandroid.ui.studymodes.testmode.studyengine.b
            r0.<init>(r7, r8)
        L18:
            java.lang.Object r8 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 0
            r4 = 1
            if (r2 == 0) goto L32
            if (r2 != r4) goto L2a
            com.quizlet.quizletandroid.ui.studymodes.testmode.studyengine.c r0 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r8)
            goto L49
        L2a:
            java.lang.IllegalStateException r8 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r8.<init>(r0)
            throw r8
        L32:
            androidx.glance.appwidget.protobuf.Z.e(r8)
            com.google.android.gms.ads.internal.client.n r8 = r7.a
            if (r8 == 0) goto L9c
            java.util.ArrayList r2 = r7.e
            if (r2 == 0) goto L96
            r0.j = r7
            r0.m = r4
            java.lang.Object r8 = r8.r(r2, r0)
            if (r8 != r1) goto L48
            return r1
        L48:
            r0 = r7
        L49:
            assistantMode.types.test.GradedTestResult r8 = (assistantMode.types.test.GradedTestResult) r8
            java.util.List r0 = r0.b
            if (r0 == 0) goto L90
            java.lang.String r1 = "<this>"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r8, r1)
            java.lang.String r1 = "shapes"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r0, r1)
            double r1 = r8.a
            java.util.ArrayList r4 = new java.util.ArrayList
            r5 = 10
            java.util.List r6 = r8.b
            int r5 = kotlin.collections.C.q(r6, r5)
            r4.<init>(r5)
            java.util.Iterator r5 = r6.iterator()
        L6c:
            boolean r6 = r5.hasNext()
            if (r6 == 0) goto L80
            java.lang.Object r6 = r5.next()
            assistantMode.types.GradedAnswer r6 = (assistantMode.types.GradedAnswer) r6
            com.quizlet.studiablemodels.grading.StudiableQuestionGradedAnswer r6 = com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3142f5.g(r6, r0)
            r4.add(r6)
            goto L6c
        L80:
            assistantMode.types.TestGeneratorOutputMetadata r8 = r8.c
            java.util.Map r8 = r8.c
            if (r8 == 0) goto L8a
            com.quizlet.studiablemodels.StudiableMeteringData r3 = com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3097a5.e(r8)
        L8a:
            com.quizlet.studiablemodels.grading.StudiableTestResults r8 = new com.quizlet.studiablemodels.grading.StudiableTestResults
            r8.<init>(r1, r4, r3)
            return r8
        L90:
            java.lang.String r8 = "diagramShapes"
            kotlin.jvm.internal.Intrinsics.m(r8)
            throw r3
        L96:
            java.lang.String r8 = "questionResponses"
            kotlin.jvm.internal.Intrinsics.m(r8)
            throw r3
        L9c:
            java.lang.String r8 = "testGenerator"
            kotlin.jvm.internal.Intrinsics.m(r8)
            throw r3
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.quizletandroid.ui.studymodes.testmode.studyengine.c.b(kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }
}

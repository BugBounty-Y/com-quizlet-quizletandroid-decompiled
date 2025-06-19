package com.quizlet.features.match.studyengine;

import com.quizlet.studiablemodels.MixedOptionMatchingStudiableQuestion;
import com.quizlet.studiablemodels.diagrams.DiagramData;
import java.util.ArrayList;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class e implements g {
    public final b a;
    public final ArrayList b;
    public DiagramData c;
    public MixedOptionMatchingStudiableQuestion d;
    public boolean e;
    public long f;
    public long g;
    public long h;

    public e(b gameEngine) {
        Intrinsics.checkNotNullParameter(gameEngine, "gameEngine");
        this.a = gameEngine;
        this.b = new ArrayList();
        this.f = -1L;
        this.g = -1L;
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object a(int r5, int r6, kotlin.coroutines.jvm.internal.c r7) {
        /*
            r4 = this;
            boolean r0 = r7 instanceof com.quizlet.features.match.studyengine.c
            if (r0 == 0) goto L13
            r0 = r7
            com.quizlet.features.match.studyengine.c r0 = (com.quizlet.features.match.studyengine.c) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L18
        L13:
            com.quizlet.features.match.studyengine.c r0 = new com.quizlet.features.match.studyengine.c
            r0.<init>(r4, r7)
        L18:
            java.lang.Object r7 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 1
            if (r2 == 0) goto L2f
            if (r2 != r3) goto L27
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto L42
        L27:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L2f:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            com.quizlet.studiablemodels.grading.MatchingGameResponse r7 = new com.quizlet.studiablemodels.grading.MatchingGameResponse
            r7.<init>(r5, r6)
            r0.l = r3
            com.quizlet.features.match.studyengine.b r5 = r4.a
            java.lang.Object r7 = r5.a(r7, r0)
            if (r7 != r1) goto L42
            return r1
        L42:
            com.quizlet.studiablemodels.grading.StudiableQuestionGradedAnswer r7 = (com.quizlet.studiablemodels.grading.StudiableQuestionGradedAnswer) r7
            boolean r5 = r7.a
            java.lang.Boolean r5 = java.lang.Boolean.valueOf(r5)
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.match.studyengine.e.a(int, int, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public final void b() {
        if (!this.e) {
            throw new IllegalStateException("No game available. Need to createMatchGame first");
        }
    }
}

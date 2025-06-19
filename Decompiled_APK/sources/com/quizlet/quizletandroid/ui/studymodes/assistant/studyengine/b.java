package com.quizlet.quizletandroid.ui.studymodes.assistant.studyengine;

import com.quizlet.studiablemodels.grading.d;
import java.util.ArrayList;

/* loaded from: classes3.dex */
public final class b implements d {
    public ArrayList a;
    public ArrayList b;
    public assistantMode.refactored.interfaces.a c;

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    @Override // com.quizlet.studiablemodels.grading.d
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object a(com.quizlet.studiablemodels.grading.StudiableQuestionResponse r6, kotlin.coroutines.jvm.internal.c r7) {
        /*
            r5 = this;
            boolean r0 = r7 instanceof com.quizlet.quizletandroid.ui.studymodes.assistant.studyengine.a
            if (r0 == 0) goto L13
            r0 = r7
            com.quizlet.quizletandroid.ui.studymodes.assistant.studyengine.a r0 = (com.quizlet.quizletandroid.ui.studymodes.assistant.studyengine.a) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            com.quizlet.quizletandroid.ui.studymodes.assistant.studyengine.a r0 = new com.quizlet.quizletandroid.ui.studymodes.assistant.studyengine.a
            r0.<init>(r5, r7)
        L18:
            java.lang.Object r7 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 0
            r4 = 1
            if (r2 == 0) goto L32
            if (r2 != r4) goto L2a
            com.quizlet.quizletandroid.ui.studymodes.assistant.studyengine.b r6 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto L4f
        L2a:
            java.lang.IllegalStateException r6 = new java.lang.IllegalStateException
            java.lang.String r7 = "call to 'resume' before 'invoke' with coroutine"
            r6.<init>(r7)
            throw r6
        L32:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            assistantMode.types.v r6 = com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3142f5.f(r6)
            assistantMode.refactored.interfaces.a r7 = r5.c
            if (r7 == 0) goto L60
            r0.j = r5
            r0.m = r4
            assistantMode.refactored.c r7 = (assistantMode.refactored.c) r7
            assistantMode.refactored.interfaces.b r2 = r7.b
            grading.core.d r7 = r7.d
            java.lang.Object r7 = r2.a(r6, r7, r0)
            if (r7 != r1) goto L4e
            return r1
        L4e:
            r6 = r5
        L4f:
            assistantMode.types.GradedAnswer r7 = (assistantMode.types.GradedAnswer) r7
            java.util.ArrayList r6 = r6.a
            if (r6 == 0) goto L5a
            com.quizlet.studiablemodels.grading.StudiableQuestionGradedAnswer r6 = com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3142f5.g(r7, r6)
            return r6
        L5a:
            java.lang.String r6 = "diagramShapes"
            kotlin.jvm.internal.Intrinsics.m(r6)
            throw r3
        L60:
            java.lang.String r6 = "studyEngine"
            kotlin.jvm.internal.Intrinsics.m(r6)
            throw r3
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.quizletandroid.ui.studymodes.assistant.studyengine.b.a(com.quizlet.studiablemodels.grading.StudiableQuestionResponse, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public final boolean b() {
        return this.c != null;
    }
}

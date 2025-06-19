package com.quizlet.features.questiontypes.mcq;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class i extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public Object j;
    public String k;
    public int l;
    public final /* synthetic */ l m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public i(l lVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.m = lVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new i(this.m, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((i) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:38:0x008c, code lost:
    
        if (com.quizlet.features.questiontypes.mcq.l.A(r1, false) != r0) goto L49;
     */
    /* JADX WARN: Code restructure failed: missing block: B:42:0x009e, code lost:
    
        if (com.quizlet.features.questiontypes.mcq.l.A(r1, false) != r0) goto L49;
     */
    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:37:0x0084 A[PHI: r1
  0x0084: PHI (r1v6 com.quizlet.features.questiontypes.mcq.l) = (r1v5 com.quizlet.features.questiontypes.mcq.l), (r1v12 com.quizlet.features.questiontypes.mcq.l) binds: [B:35:0x0081, B:14:0x0031] A[DONT_GENERATE, DONT_INLINE]] */
    /* JADX WARN: Type inference failed for: r1v0, types: [int] */
    /* JADX WARN: Type inference failed for: r1v8 */
    /* JADX WARN: Type inference failed for: r1v9 */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r11) throws java.lang.Throwable {
        /*
            r10 = this;
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r10.l
            r2 = 5
            r3 = 4
            r4 = 3
            r5 = 2
            r6 = 0
            r7 = 1
            r8 = 0
            if (r1 == 0) goto L4c
            if (r1 == r7) goto L3a
            if (r1 == r5) goto L2d
            if (r1 == r4) goto L28
            if (r1 == r3) goto L28
            if (r1 == r2) goto L1f
            java.lang.IllegalStateException r11 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r11.<init>(r0)
            throw r11
        L1f:
            java.lang.Object r0 = r10.j
            java.lang.Throwable r0 = (java.lang.Throwable) r0
            androidx.glance.appwidget.protobuf.Z.e(r11)
            goto Laf
        L28:
            androidx.glance.appwidget.protobuf.Z.e(r11)
            goto Lb0
        L2d:
            java.lang.Object r1 = r10.j
            com.quizlet.features.questiontypes.mcq.l r1 = (com.quizlet.features.questiontypes.mcq.l) r1
            androidx.glance.appwidget.protobuf.Z.e(r11)     // Catch: java.lang.Throwable -> L35 java.io.IOException -> L38
            goto L84
        L35:
            r11 = move-exception
            goto La1
        L38:
            r11 = move-exception
            goto L8f
        L3a:
            java.lang.String r1 = r10.k
            java.lang.Object r7 = r10.j
            com.quizlet.features.questiontypes.mcq.l r7 = (com.quizlet.features.questiontypes.mcq.l) r7
            androidx.glance.appwidget.protobuf.Z.e(r11)     // Catch: java.lang.Throwable -> L46 java.io.IOException -> L49
            r11 = r1
            r1 = r7
            goto L71
        L46:
            r11 = move-exception
            r1 = r7
            goto La1
        L49:
            r11 = move-exception
            r1 = r7
            goto L8f
        L4c:
            androidx.glance.appwidget.protobuf.Z.e(r11)
            com.quizlet.features.questiontypes.mcq.l r1 = r10.m
            com.quizlet.studiablemodels.MultipleChoiceStudiableQuestion r11 = r1.i
            com.quizlet.studiablemodels.QuestionSectionData r11 = r11.b
            java.lang.String r9 = "null cannot be cast to non-null type com.quizlet.studiablemodels.DefaultQuestionSectionData"
            kotlin.jvm.internal.Intrinsics.e(r11, r9)
            com.quizlet.studiablemodels.DefaultQuestionSectionData r11 = (com.quizlet.studiablemodels.DefaultQuestionSectionData) r11
            com.quizlet.studiablemodels.StudiableAudio r11 = r11.c
            if (r11 == 0) goto Lb0
            java.lang.String r11 = r11.a
            if (r11 == 0) goto Lb0
            r10.j = r1     // Catch: java.lang.Throwable -> L35 java.io.IOException -> L38
            r10.k = r11     // Catch: java.lang.Throwable -> L35 java.io.IOException -> L38
            r10.l = r7     // Catch: java.lang.Throwable -> L35 java.io.IOException -> L38
            kotlin.Unit r7 = com.quizlet.features.questiontypes.mcq.l.A(r1, r7)     // Catch: java.lang.Throwable -> L35 java.io.IOException -> L38
            if (r7 != r0) goto L71
            goto Lad
        L71:
            com.quizlet.quizletandroid.managers.audio.h r7 = r1.e     // Catch: java.lang.Throwable -> L35 java.io.IOException -> L38
            io.reactivex.rxjava3.internal.operators.completable.a r11 = r7.a(r11)     // Catch: java.lang.Throwable -> L35 java.io.IOException -> L38
            r10.j = r1     // Catch: java.lang.Throwable -> L35 java.io.IOException -> L38
            r10.k = r8     // Catch: java.lang.Throwable -> L35 java.io.IOException -> L38
            r10.l = r5     // Catch: java.lang.Throwable -> L35 java.io.IOException -> L38
            java.lang.Object r11 = com.google.android.gms.internal.mlkit_vision_camera.I1.a(r11, r10)     // Catch: java.lang.Throwable -> L35 java.io.IOException -> L38
            if (r11 != r0) goto L84
            goto Lad
        L84:
            r10.j = r8
            r10.l = r4
            kotlin.Unit r11 = com.quizlet.features.questiontypes.mcq.l.A(r1, r6)
            if (r11 != r0) goto Lb0
            goto Lad
        L8f:
            timber.log.a r4 = timber.log.c.a     // Catch: java.lang.Throwable -> L35
            r4.e(r11)     // Catch: java.lang.Throwable -> L35
            r10.j = r8
            r10.k = r8
            r10.l = r3
            kotlin.Unit r11 = com.quizlet.features.questiontypes.mcq.l.A(r1, r6)
            if (r11 != r0) goto Lb0
            goto Lad
        La1:
            r10.j = r11
            r10.k = r8
            r10.l = r2
            kotlin.Unit r1 = com.quizlet.features.questiontypes.mcq.l.A(r1, r6)
            if (r1 != r0) goto Lae
        Lad:
            return r0
        Lae:
            r0 = r11
        Laf:
            throw r0
        Lb0:
            kotlin.Unit r11 = kotlin.Unit.a
            return r11
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.questiontypes.mcq.i.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}

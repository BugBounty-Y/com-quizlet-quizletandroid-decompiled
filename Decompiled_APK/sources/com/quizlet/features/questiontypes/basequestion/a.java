package com.quizlet.features.questiontypes.basequestion;

import com.quizlet.studiablemodels.grading.StudiableQuestionGradedAnswer;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class a extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public /* synthetic */ Object k;
    public final /* synthetic */ boolean l;
    public final /* synthetic */ StudiableQuestionGradedAnswer m;
    public final /* synthetic */ kotlin.coroutines.jvm.internal.i n;
    public final /* synthetic */ com.quizlet.quizletandroid.managers.audio.h o;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    /* JADX WARN: Multi-variable type inference failed */
    public a(boolean z, StudiableQuestionGradedAnswer studiableQuestionGradedAnswer, Function2 function2, com.quizlet.quizletandroid.managers.audio.h hVar, kotlin.coroutines.h hVar2) {
        super(2, hVar2);
        this.l = z;
        this.m = studiableQuestionGradedAnswer;
        this.n = (kotlin.coroutines.jvm.internal.i) function2;
        this.o = hVar;
    }

    /* JADX WARN: Type inference failed for: r3v0, types: [kotlin.coroutines.jvm.internal.i, kotlin.jvm.functions.Function2] */
    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        a aVar = new a(this.l, this.m, this.n, this.o, hVar);
        aVar.k = obj;
        return aVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((a) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:40:0x0081, code lost:
    
        if (r2.invoke(r1, r9) == r0) goto L55;
     */
    /* JADX WARN: Code restructure failed: missing block: B:44:0x0093, code lost:
    
        if (r2.invoke(r1, r9) != r0) goto L56;
     */
    /* JADX WARN: Code restructure failed: missing block: B:54:0x00af, code lost:
    
        if (r2.invoke(r1, r9) == r0) goto L55;
     */
    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r1v0, types: [int] */
    /* JADX WARN: Type inference failed for: r1v10 */
    /* JADX WARN: Type inference failed for: r1v11 */
    /* JADX WARN: Type inference failed for: r1v7 */
    /* JADX WARN: Type inference failed for: r2v0, types: [kotlin.coroutines.jvm.internal.i, kotlin.jvm.functions.Function2] */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r10) throws java.lang.Throwable {
        /*
            r9 = this;
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r9.j
            kotlin.coroutines.jvm.internal.i r2 = r9.n
            r3 = 5
            r4 = 4
            r5 = 3
            r6 = 2
            r7 = 1
            if (r1 == 0) goto L3d
            if (r1 == r7) goto L2c
            if (r1 == r6) goto L31
            if (r1 == r5) goto L28
            if (r1 == r4) goto L28
            if (r1 == r3) goto L1f
            java.lang.IllegalStateException r10 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r10.<init>(r0)
            throw r10
        L1f:
            java.lang.Object r0 = r9.k
            java.lang.Throwable r0 = (java.lang.Throwable) r0
            androidx.glance.appwidget.protobuf.Z.e(r10)
            goto La2
        L28:
            java.lang.Object r0 = r9.k
            kotlin.Unit r0 = (kotlin.Unit) r0
        L2c:
            androidx.glance.appwidget.protobuf.Z.e(r10)
            goto Lb2
        L31:
            java.lang.Object r1 = r9.k
            kotlinx.coroutines.C r1 = (kotlinx.coroutines.C) r1
            androidx.glance.appwidget.protobuf.Z.e(r10)     // Catch: java.lang.Throwable -> L39 java.io.IOException -> L3b
            goto L75
        L39:
            r10 = move-exception
            goto L96
        L3b:
            r10 = move-exception
            goto L84
        L3d:
            androidx.glance.appwidget.protobuf.Z.e(r10)
            java.lang.Object r10 = r9.k
            r1 = r10
            kotlinx.coroutines.C r1 = (kotlinx.coroutines.C) r1
            boolean r10 = r9.l
            if (r10 == 0) goto La9
            com.quizlet.studiablemodels.grading.StudiableQuestionGradedAnswer r10 = r9.m
            com.quizlet.studiablemodels.grading.StudiableQuestionFeedback r10 = r10.b
            com.quizlet.studiablemodels.QuestionSectionData r10 = r10.c
            boolean r8 = r10 instanceof com.quizlet.studiablemodels.LocationQuestionSectionData
            if (r8 == 0) goto L54
            goto La9
        L54:
            if (r8 != 0) goto Lb2
            boolean r7 = r10 instanceof com.quizlet.studiablemodels.DefaultQuestionSectionData
            if (r7 == 0) goto La3
            com.quizlet.studiablemodels.DefaultQuestionSectionData r10 = (com.quizlet.studiablemodels.DefaultQuestionSectionData) r10     // Catch: java.lang.Throwable -> L39 java.io.IOException -> L3b
            com.quizlet.studiablemodels.StudiableAudio r10 = r10.c     // Catch: java.lang.Throwable -> L39 java.io.IOException -> L3b
            if (r10 == 0) goto L78
            java.lang.String r10 = r10.a     // Catch: java.lang.Throwable -> L39 java.io.IOException -> L3b
            if (r10 == 0) goto L78
            com.quizlet.quizletandroid.managers.audio.h r7 = r9.o     // Catch: java.lang.Throwable -> L39 java.io.IOException -> L3b
            io.reactivex.rxjava3.internal.operators.completable.a r10 = r7.a(r10)     // Catch: java.lang.Throwable -> L39 java.io.IOException -> L3b
            r9.k = r1     // Catch: java.lang.Throwable -> L39 java.io.IOException -> L3b
            r9.j = r6     // Catch: java.lang.Throwable -> L39 java.io.IOException -> L3b
            java.lang.Object r10 = com.google.android.gms.internal.mlkit_vision_camera.I1.a(r10, r9)     // Catch: java.lang.Throwable -> L39 java.io.IOException -> L3b
            if (r10 != r0) goto L75
            goto Lb1
        L75:
            kotlin.Unit r10 = kotlin.Unit.a     // Catch: java.lang.Throwable -> L39 java.io.IOException -> L3b
            goto L79
        L78:
            r10 = 0
        L79:
            r9.k = r10
            r9.j = r5
            java.lang.Object r10 = r2.invoke(r1, r9)
            if (r10 != r0) goto Lb2
            goto Lb1
        L84:
            timber.log.a r5 = timber.log.c.a     // Catch: java.lang.Throwable -> L39
            r5.e(r10)     // Catch: java.lang.Throwable -> L39
            kotlin.Unit r10 = kotlin.Unit.a     // Catch: java.lang.Throwable -> L39
            r9.k = r10
            r9.j = r4
            java.lang.Object r10 = r2.invoke(r1, r9)
            if (r10 != r0) goto Lb2
            goto Lb1
        L96:
            r9.k = r10
            r9.j = r3
            java.lang.Object r1 = r2.invoke(r1, r9)
            if (r1 != r0) goto La1
            goto Lb1
        La1:
            r0 = r10
        La2:
            throw r0
        La3:
            kotlin.NoWhenBranchMatchedException r10 = new kotlin.NoWhenBranchMatchedException
            r10.<init>()
            throw r10
        La9:
            r9.j = r7
            java.lang.Object r10 = r2.invoke(r1, r9)
            if (r10 != r0) goto Lb2
        Lb1:
            return r0
        Lb2:
            kotlin.Unit r10 = kotlin.Unit.a
            return r10
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.questiontypes.basequestion.a.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}

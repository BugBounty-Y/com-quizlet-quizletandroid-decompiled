package com.quizlet.features.questiontypes.mcq;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class f extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ com.quizlet.features.questiontypes.mcq.data.d k;
    public final /* synthetic */ l l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public f(l lVar, com.quizlet.features.questiontypes.mcq.data.d dVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = dVar;
        this.l = lVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new f(this.l, this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((f) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:19:0x004e, code lost:
    
        if (r15 == r0) goto L28;
     */
    /* JADX WARN: Code restructure failed: missing block: B:22:0x005a, code lost:
    
        if (kotlin.Unit.a == r0) goto L28;
     */
    /* JADX WARN: Code restructure failed: missing block: B:27:0x006a, code lost:
    
        if (kotlin.Unit.a == r0) goto L28;
     */
    /* JADX WARN: Code restructure failed: missing block: B:28:0x006c, code lost:
    
        return r0;
     */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r15) {
        /*
            r14 = this;
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r14.j
            r2 = 3
            r3 = 2
            r4 = 1
            if (r1 == 0) goto L1c
            if (r1 == r4) goto L18
            if (r1 == r3) goto L18
            if (r1 != r2) goto L10
            goto L18
        L10:
            java.lang.IllegalStateException r15 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r15.<init>(r0)
            throw r15
        L18:
            androidx.glance.appwidget.protobuf.Z.e(r15)
            goto L6d
        L1c:
            androidx.glance.appwidget.protobuf.Z.e(r15)
            com.quizlet.features.questiontypes.mcq.data.d r15 = r14.k
            com.google.android.gms.internal.mlkit_vision_camera.Y2 r1 = r15.b
            boolean r5 = r1 instanceof com.quizlet.features.questiontypes.mcq.data.c
            com.quizlet.features.questiontypes.basequestion.data.a r6 = r15.d
            com.quizlet.features.questiontypes.mcq.l r7 = r14.l
            if (r5 == 0) goto L5d
            com.quizlet.features.questiontypes.mcq.data.c r1 = (com.quizlet.features.questiontypes.mcq.data.c) r1
            com.quizlet.studiablemodels.grading.StudiableQuestionGradedAnswer r10 = r1.c
            if (r10 == 0) goto L51
            com.quizlet.quizletandroid.managers.audio.h r12 = r7.e
            com.quizlet.features.infra.studysetting.data.QuestionSettings r1 = r7.h
            boolean r9 = r1.c
            com.quizlet.features.questiontypes.mcq.e r11 = new com.quizlet.features.questiontypes.mcq.e
            r1 = 0
            r11.<init>(r7, r15, r1)
            r14.j = r4
            com.quizlet.features.questiontypes.basequestion.b r8 = new com.quizlet.features.questiontypes.basequestion.b
            r13 = 0
            r8.<init>(r9, r10, r11, r12, r13)
            java.lang.Object r15 = kotlinx.coroutines.E.m(r8, r14)
            if (r15 != r0) goto L4c
            goto L4e
        L4c:
            kotlin.Unit r15 = kotlin.Unit.a
        L4e:
            if (r15 != r0) goto L6d
            goto L6c
        L51:
            kotlinx.coroutines.flow.s0 r15 = r7.s
            r14.j = r3
            r15.l(r6)
            kotlin.Unit r15 = kotlin.Unit.a
            if (r15 != r0) goto L6d
            goto L6c
        L5d:
            boolean r15 = r1 instanceof com.quizlet.features.questiontypes.mcq.data.b
            if (r15 == 0) goto L70
            kotlinx.coroutines.flow.s0 r15 = r7.s
            r14.j = r2
            r15.l(r6)
            kotlin.Unit r15 = kotlin.Unit.a
            if (r15 != r0) goto L6d
        L6c:
            return r0
        L6d:
            kotlin.Unit r15 = kotlin.Unit.a
            return r15
        L70:
            kotlin.NoWhenBranchMatchedException r15 = new kotlin.NoWhenBranchMatchedException
            r15.<init>()
            throw r15
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.questiontypes.mcq.f.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}

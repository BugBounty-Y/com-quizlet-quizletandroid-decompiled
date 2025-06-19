package com.quizlet.features.questiontypes.truefalse;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class h extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public m j;
    public int k;
    public final /* synthetic */ l l;
    public final /* synthetic */ boolean m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public h(l lVar, boolean z, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = lVar;
        this.m = z;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new h(this.l, this.m, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((h) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:23:0x0095, code lost:
    
        if (kotlin.Unit.a != r1) goto L25;
     */
    /* JADX WARN: Removed duplicated region for block: B:20:0x0076  */
    /* JADX WARN: Removed duplicated region for block: B:21:0x0079  */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r23) {
        /*
            r22 = this;
            r0 = r22
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.k
            com.quizlet.features.questiontypes.truefalse.l r3 = r0.l
            r4 = 0
            boolean r5 = r0.m
            r6 = 3
            r7 = 2
            r8 = 1
            com.quizlet.studiablemodels.TrueFalseStudiableQuestion r9 = r3.i
            if (r2 == 0) goto L31
            if (r2 == r8) goto L2b
            if (r2 == r7) goto L25
            if (r2 != r6) goto L1d
            androidx.glance.appwidget.protobuf.Z.e(r23)
            goto L98
        L1d:
            java.lang.IllegalStateException r1 = new java.lang.IllegalStateException
            java.lang.String r2 = "call to 'resume' before 'invoke' with coroutine"
            r1.<init>(r2)
            throw r1
        L25:
            com.quizlet.features.questiontypes.truefalse.m r2 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r23)
            goto L68
        L2b:
            androidx.glance.appwidget.protobuf.Z.e(r23)
            r2 = r23
            goto L48
        L31:
            androidx.glance.appwidget.protobuf.Z.e(r23)
            com.quizlet.studiablemodels.grading.TrueFalseResponse r2 = new com.quizlet.studiablemodels.grading.TrueFalseResponse
            r2.<init>(r5)
            r0.k = r8
            com.quizlet.data.repository.set.f r8 = r3.c
            com.quizlet.studiablemodels.grading.d r10 = r3.k
            boolean r11 = r3.j
            java.lang.Object r2 = r8.o(r10, r2, r11, r0)
            if (r2 != r1) goto L48
            goto L97
        L48:
            com.quizlet.features.questiontypes.truefalse.m r2 = (com.quizlet.features.questiontypes.truefalse.m) r2
            kotlinx.coroutines.flow.d0 r8 = r3.p
            com.quizlet.features.questiontypes.basequestion.f r10 = new com.quizlet.features.questiontypes.basequestion.f
            com.quizlet.features.questiontypes.truefalse.d r11 = r2.c
            com.quizlet.features.questiontypes.data.a r11 = r11.c
            java.lang.Boolean r11 = r11.b
            java.lang.Boolean r12 = java.lang.Boolean.TRUE
            boolean r11 = kotlin.jvm.internal.Intrinsics.b(r11, r12)
            r10.<init>(r11)
            r0.j = r2
            r0.k = r7
            java.lang.Object r7 = r8.emit(r10, r0)
            if (r7 != r1) goto L68
            goto L97
        L68:
            com.quizlet.features.questiontypes.truefalse.d r7 = r2.c
            com.quizlet.features.questiontypes.data.a r7 = r7.c
            java.lang.Boolean r7 = r7.b
            java.lang.Boolean r8 = java.lang.Boolean.TRUE
            boolean r7 = kotlin.jvm.internal.Intrinsics.b(r7, r8)
            if (r7 == 0) goto L79
            assistantMode.enums.f r7 = assistantMode.enums.EnumC1452f.c
            goto L7b
        L79:
            assistantMode.enums.f r7 = assistantMode.enums.EnumC1452f.b
        L7b:
            com.quizlet.quizletandroid.ui.studymodes.questionTypes.managers.a r8 = r3.b
            int r7 = r7.a
            long r10 = r3.g
            com.quizlet.db.data.models.persisted.DBAnswer r7 = r8.b(r9, r7, r10)
            r3.r = r7
            r0.j = r4
            r0.k = r6
            kotlinx.coroutines.flow.s0 r6 = r3.l
            r6.getClass()
            r6.m(r4, r2)
            kotlin.Unit r2 = kotlin.Unit.a
            if (r2 != r1) goto L98
        L97:
            return r1
        L98:
            com.quizlet.db.data.models.persisted.DBAnswer r1 = r3.r
            if (r1 == 0) goto Lc8
            com.quizlet.eventlogger.features.basequestion.QuestionEventLogData$Companion r2 = com.quizlet.eventlogger.features.basequestion.QuestionEventLogData.a
            r2.getClass()
            com.quizlet.eventlogger.features.basequestion.QuestionEventLogData r13 = com.quizlet.eventlogger.features.basequestion.QuestionEventLogData.Companion.a(r9)
            int r1 = r1.getCorrectness()
            java.lang.Integer r15 = java.lang.Integer.valueOf(r1)
            java.lang.String r16 = java.lang.String.valueOf(r5)
            r19 = 0
            r20 = 0
            com.quizlet.eventlogger.features.basequestion.QuestionEventLogger r10 = r3.d
            java.lang.String r11 = r3.f
            java.lang.String r12 = "answer"
            r14 = 4
            r17 = 0
            r18 = 0
            r21 = 1920(0x780, float:2.69E-42)
            com.quizlet.eventlogger.features.basequestion.QuestionEventLogger.DefaultImpls.a(r10, r11, r12, r13, r14, r15, r16, r17, r18, r19, r20, r21)
            kotlin.Unit r1 = kotlin.Unit.a
            return r1
        Lc8:
            java.lang.String r1 = "answer"
            kotlin.jvm.internal.Intrinsics.m(r1)
            throw r4
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.questiontypes.truefalse.h.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}

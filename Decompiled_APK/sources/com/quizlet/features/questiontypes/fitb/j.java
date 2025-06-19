package com.quizlet.features.questiontypes.fitb;

import java.util.List;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class j extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public g j;
    public int k;
    public final /* synthetic */ List l;
    public final /* synthetic */ m m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public j(List list, m mVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = list;
        this.m = mVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new j(this.l, this.m, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((j) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:22:0x00ae, code lost:
    
        if (kotlin.Unit.a != r6) goto L24;
     */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r19) {
        /*
            r18 = this;
            r5 = r18
            kotlin.coroutines.intrinsics.a r6 = kotlin.coroutines.intrinsics.a.a
            int r0 = r5.k
            r7 = 3
            r8 = 2
            r1 = 1
            com.quizlet.features.questiontypes.fitb.m r9 = r5.m
            if (r0 == 0) goto L2c
            if (r0 == r1) goto L26
            if (r0 == r8) goto L20
            if (r0 != r7) goto L18
            androidx.glance.appwidget.protobuf.Z.e(r19)
            goto Lb1
        L18:
            java.lang.IllegalStateException r0 = new java.lang.IllegalStateException
            java.lang.String r1 = "call to 'resume' before 'invoke' with coroutine"
            r0.<init>(r1)
            throw r0
        L20:
            com.quizlet.features.questiontypes.fitb.g r0 = r5.j
            androidx.glance.appwidget.protobuf.Z.e(r19)
            goto L8f
        L26:
            androidx.glance.appwidget.protobuf.Z.e(r19)
            r0 = r19
            goto L6d
        L2c:
            androidx.glance.appwidget.protobuf.Z.e(r19)
            com.quizlet.studiablemodels.grading.FillInTheBlankResponse r2 = new com.quizlet.studiablemodels.grading.FillInTheBlankResponse
            java.util.List r0 = r5.l
            if (r0 != 0) goto L37
            kotlin.collections.K r0 = kotlin.collections.K.a
        L37:
            r2.<init>(r0)
            com.quizlet.data.repository.login.a r0 = r9.d
            com.quizlet.features.notes.paywall.a r3 = new com.quizlet.features.notes.paywall.a
            java.lang.Class<com.quizlet.features.questiontypes.fitb.m> r13 = com.quizlet.features.questiontypes.fitb.m.class
            java.lang.String r14 = "onContinueClick"
            r11 = 0
            com.quizlet.features.questiontypes.fitb.m r12 = r5.m
            java.lang.String r15 = "onContinueClick$questiontypes_release()V"
            r16 = 0
            r17 = 9
            r10 = r3
            r10.<init>(r11, r12, r13, r14, r15, r16, r17)
            com.quizlet.features.notes.paywall.a r4 = new com.quizlet.features.notes.paywall.a
            java.lang.Class<com.quizlet.features.questiontypes.fitb.m> r13 = com.quizlet.features.questiontypes.fitb.m.class
            java.lang.String r14 = "onIWasCorrectClick"
            r11 = 0
            com.quizlet.features.questiontypes.fitb.m r12 = r5.m
            java.lang.String r15 = "onIWasCorrectClick$questiontypes_release()V"
            r16 = 0
            r17 = 10
            r10 = r4
            r10.<init>(r11, r12, r13, r14, r15, r16, r17)
            r5.k = r1
            com.quizlet.studiablemodels.grading.d r1 = r9.g
            java.lang.Object r0 = r0.g(r1, r2, r3, r4, r5)
            if (r0 != r6) goto L6d
            goto Lb0
        L6d:
            com.quizlet.features.questiontypes.fitb.g r0 = (com.quizlet.features.questiontypes.fitb.g) r0
            kotlinx.coroutines.flow.d0 r1 = r9.l
            com.quizlet.features.questiontypes.basequestion.f r2 = new com.quizlet.features.questiontypes.basequestion.f
            androidx.compose.animation.core.J0 r3 = r0.c
            com.quizlet.features.questiontypes.data.a r3 = r3.x()
            java.lang.Boolean r3 = r3.b
            java.lang.Boolean r4 = java.lang.Boolean.TRUE
            boolean r3 = kotlin.jvm.internal.Intrinsics.b(r3, r4)
            r2.<init>(r3)
            r5.j = r0
            r5.k = r8
            java.lang.Object r1 = r1.emit(r2, r5)
            if (r1 != r6) goto L8f
            goto Lb0
        L8f:
            androidx.compose.animation.core.J0 r1 = r0.c
            boolean r1 = r1 instanceof com.quizlet.features.questiontypes.fitb.a
            long r2 = r9.e
            com.quizlet.quizletandroid.ui.studymodes.questionTypes.managers.a r4 = r9.b
            com.quizlet.studiablemodels.FillInTheBlankStudiableQuestion r8 = r9.f
            com.quizlet.db.data.models.persisted.DBAnswer r1 = r4.b(r8, r1, r2)
            r9.n = r1
            r1 = 0
            r5.j = r1
            r5.k = r7
            kotlinx.coroutines.flow.s0 r2 = r9.h
            r2.getClass()
            r2.m(r1, r0)
            kotlin.Unit r0 = kotlin.Unit.a
            if (r0 != r6) goto Lb1
        Lb0:
            return r6
        Lb1:
            kotlin.Unit r0 = kotlin.Unit.a
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.questiontypes.fitb.j.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}

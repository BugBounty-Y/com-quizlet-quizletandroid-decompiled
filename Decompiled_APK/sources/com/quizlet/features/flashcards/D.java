package com.quizlet.features.flashcards;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes2.dex */
public final class D extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ S k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public D(S s, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = s;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new D(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((D) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:25:0x00b0, code lost:
    
        if (com.quizlet.features.flashcards.S.D(r5, r17) == r1) goto L26;
     */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r18) {
        /*
            r17 = this;
            r0 = r17
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.j
            r3 = 1
            r4 = 2
            com.quizlet.features.flashcards.S r5 = r0.k
            if (r2 == 0) goto L23
            if (r2 == r3) goto L1d
            if (r2 != r4) goto L15
            androidx.glance.appwidget.protobuf.Z.e(r18)
            goto Lb3
        L15:
            java.lang.IllegalStateException r1 = new java.lang.IllegalStateException
            java.lang.String r2 = "call to 'resume' before 'invoke' with coroutine"
            r1.<init>(r2)
            throw r1
        L1d:
            androidx.glance.appwidget.protobuf.Z.e(r18)
            r2 = r18
            goto L93
        L23:
            androidx.glance.appwidget.protobuf.Z.e(r18)
            com.quizlet.features.flashcards.logging.a r2 = r5.h
            java.lang.String r6 = com.quizlet.features.flashcards.S.C(r5)
            com.quizlet.features.flashcards.engine.h r7 = r5.c
            com.quizlet.features.infra.models.flashcards.d r7 = r7.d()
            com.quizlet.features.infra.models.flashcards.c r7 = r7.b()
            com.quizlet.features.infra.models.flashcards.c r8 = com.quizlet.features.infra.models.flashcards.c.c
            if (r7 != r8) goto L3c
            r7 = r3
            goto L3d
        L3c:
            r7 = 0
        L3d:
            r2.getClass()
            java.lang.String r8 = "studyModeScreen"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r6, r8)
            com.quizlet.eventlogger.features.flashcards.FlashcardsEventLog$Companion r8 = com.quizlet.eventlogger.features.flashcards.FlashcardsEventLog.b
            r8.getClass()
            java.lang.String r8 = "action"
            java.lang.String r9 = "flashcards_next_action_button_clicked"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r9, r8)
            com.quizlet.eventlogger.features.flashcards.FlashcardsEventPayload r10 = new com.quizlet.eventlogger.features.flashcards.FlashcardsEventPayload
            r13 = 0
            r14 = 0
            r11 = 0
            r12 = 0
            r15 = 15
            r16 = 0
            r10.<init>(r11, r12, r13, r14, r15, r16)
            if (r7 == 0) goto L63
            java.lang.String r7 = "QUIZ_MODE"
            goto L65
        L63:
            java.lang.String r7 = "REVIEW_MODE"
        L65:
            r10.setSortingMode(r7)
            java.lang.String r7 = "$this$createEvent"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r10, r7)
            java.lang.String r7 = "flashcards_to_learn"
            r10.setNextAction(r7)
            r10.setScreenName(r6)
            kotlin.Unit r6 = kotlin.Unit.a
            com.quizlet.eventlogger.features.flashcards.FlashcardsEventLog r6 = new com.quizlet.eventlogger.features.flashcards.FlashcardsEventLog
            r6.<init>(r10)
            r6.setAction(r9)
            com.quizlet.eventlogger.EventLogger r2 = r2.a
            r2.l(r6)
            androidx.work.impl.model.c r2 = r5.i
            io.reactivex.rxjava3.internal.operators.single.g r2 = r2.r()
            r0.j = r3
            java.lang.Object r2 = com.google.android.gms.internal.mlkit_vision_camera.I1.b(r2, r0)
            if (r2 != r1) goto L93
            goto Lb2
        L93:
            java.lang.Boolean r2 = (java.lang.Boolean) r2
            boolean r2 = r2.booleanValue()
            if (r2 == 0) goto Laa
            com.quizlet.generated.enums.A1 r1 = com.quizlet.generated.enums.A1.LEARNING_ASSISTANT
            kotlinx.coroutines.flow.d0 r2 = r5.r
            com.quizlet.features.flashcards.data.j r3 = new com.quizlet.features.flashcards.data.j
            long r4 = r5.m
            r3.<init>(r4, r1)
            r2.h(r3)
            goto Lb3
        Laa:
            r0.j = r4
            java.lang.Object r2 = com.quizlet.features.flashcards.S.D(r5, r0)
            if (r2 != r1) goto Lb3
        Lb2:
            return r1
        Lb3:
            kotlin.Unit r1 = kotlin.Unit.a
            return r1
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.flashcards.D.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}

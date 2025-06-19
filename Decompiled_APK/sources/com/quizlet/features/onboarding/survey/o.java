package com.quizlet.features.onboarding.survey;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class o extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ q k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public o(q qVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = qVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new o(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((o) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:17:0x00a5, code lost:
    
        if (r10.emit(r1, r9) == r0) goto L18;
     */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r10) {
        /*
            r9 = this;
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r9.j
            r2 = 0
            r3 = 2
            com.quizlet.features.onboarding.survey.q r4 = r9.k
            r5 = 1
            if (r1 == 0) goto L20
            if (r1 == r5) goto L1c
            if (r1 != r3) goto L14
            androidx.glance.appwidget.protobuf.Z.e(r10)
            goto La8
        L14:
            java.lang.IllegalStateException r10 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r10.<init>(r0)
            throw r10
        L1c:
            androidx.glance.appwidget.protobuf.Z.e(r10)
            goto L5b
        L20:
            androidx.glance.appwidget.protobuf.Z.e(r10)
            com.quizlet.local.datastore.preferences.n0 r10 = r4.c
            r9.j = r5
            r10.getClass()
            java.lang.Long r1 = new java.lang.Long
            long r6 = r4.b
            r1.<init>(r6)
            java.lang.Object[] r1 = new java.lang.Object[]{r1}
            java.lang.Object[] r1 = java.util.Arrays.copyOf(r1, r5)
            java.lang.String r6 = "user_completed_onboarding_survey_%s"
            java.lang.String r1 = java.lang.String.format(r6, r1)
            java.lang.String r6 = "format(...)"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r1, r6)
            androidx.datastore.preferences.core.f r1 = com.google.android.gms.internal.mlkit_vision_barcode.R6.a(r1)
            com.quizlet.local.datastore.preferences.m0 r6 = new com.quizlet.local.datastore.preferences.m0
            r6.<init>(r1, r2)
            androidx.datastore.core.h r10 = r10.a
            java.lang.Object r10 = com.google.android.gms.internal.mlkit_vision_barcode.S6.d(r10, r6, r9)
            if (r10 != r0) goto L56
            goto L58
        L56:
            kotlin.Unit r10 = kotlin.Unit.a
        L58:
            if (r10 != r0) goto L5b
            goto La7
        L5b:
            com.quizlet.features.onboarding.survey.k r10 = r4.d
            kotlinx.coroutines.flow.s0 r1 = r4.e
            java.lang.Object r1 = r1.getValue()
            com.quizlet.features.onboarding.survey.n r1 = (com.quizlet.features.onboarding.survey.n) r1
            com.quizlet.features.onboarding.survey.m r1 = r1.b
            r10.getClass()
            java.lang.String r6 = "source"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r1, r6)
            com.quizlet.eventlogger.model.OnboardingSurveyEventLog$Companion r6 = com.quizlet.eventlogger.model.OnboardingSurveyEventLog.b
            com.quizlet.features.folders.composables.J r7 = new com.quizlet.features.folders.composables.J
            r8 = 7
            r7.<init>(r1, r8)
            r6.getClass()
            java.lang.String r1 = "action"
            java.lang.String r6 = "onboarding_survey_source_selected"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r6, r1)
            java.lang.String r1 = "payloadModifier"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r7, r1)
            com.quizlet.eventlogger.model.OnboardingSurveyEventLog$Payload r1 = new com.quizlet.eventlogger.model.OnboardingSurveyEventLog$Payload
            r1.<init>(r2, r5, r2)
            r7.invoke(r1)
            com.quizlet.eventlogger.model.OnboardingSurveyEventLog r2 = new com.quizlet.eventlogger.model.OnboardingSurveyEventLog
            r2.<init>(r1)
            r2.setAction(r6)
            com.quizlet.eventlogger.EventLogger r10 = r10.a
            r10.l(r2)
            kotlinx.coroutines.flow.d0 r10 = r4.f
            com.quizlet.features.onboarding.survey.l r1 = com.quizlet.features.onboarding.survey.l.a
            r9.j = r3
            java.lang.Object r10 = r10.emit(r1, r9)
            if (r10 != r0) goto La8
        La7:
            return r0
        La8:
            kotlin.Unit r10 = kotlin.Unit.a
            return r10
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.onboarding.survey.o.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}

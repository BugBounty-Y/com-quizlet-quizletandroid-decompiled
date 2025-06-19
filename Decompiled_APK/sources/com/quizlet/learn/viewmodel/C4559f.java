package com.quizlet.learn.viewmodel;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: com.quizlet.learn.viewmodel.f, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4559f extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ i k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C4559f(i iVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = iVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new C4559f(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C4559f) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:18:0x006c, code lost:
    
        if (kotlin.Unit.a == r0) goto L19;
     */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r12) {
        /*
            r11 = this;
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r11.j
            r2 = 2
            r3 = 1
            com.quizlet.learn.viewmodel.i r4 = r11.k
            if (r1 == 0) goto L1e
            if (r1 == r3) goto L1a
            if (r1 != r2) goto L12
            androidx.glance.appwidget.protobuf.Z.e(r12)
            goto L6f
        L12:
            java.lang.IllegalStateException r12 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r12.<init>(r0)
            throw r12
        L1a:
            androidx.glance.appwidget.protobuf.Z.e(r12)
            goto L2e
        L1e:
            androidx.glance.appwidget.protobuf.Z.e(r12)
            com.quizlet.data.repository.course.membership.c r12 = r4.b
            r11.j = r3
            com.quizlet.generated.enums.G1 r1 = r4.g
            java.lang.Object r12 = r12.j(r1, r11)
            if (r12 != r0) goto L2e
            goto L6e
        L2e:
            com.quizlet.learn.data.onboarding.d r12 = (com.quizlet.learn.data.onboarding.d) r12
            com.quizlet.eventlogger.features.learnonboarding.LearnOnboardingEventLogger r1 = r4.c
            java.util.ArrayList r5 = com.quizlet.learn.viewmodel.i.A(r12)
            r1.getClass()
            if (r5 == 0) goto L4c
            com.quizlet.assembly.compose.buttons.Z r9 = new com.quizlet.assembly.compose.buttons.Z
            r3 = 15
            r9.<init>(r3)
            r8 = 0
            r10 = 31
            r6 = 0
            r7 = 0
            java.lang.String r3 = kotlin.collections.CollectionsKt.S(r5, r6, r7, r8, r9, r10)
            goto L4d
        L4c:
            r3 = 0
        L4d:
            com.quizlet.eventlogger.features.learnonboarding.LearnOnboardingEventLog$Companion r5 = com.quizlet.eventlogger.features.learnonboarding.LearnOnboardingEventLog.b
            com.quizlet.eventlogger.features.learnonboarding.c r6 = new com.quizlet.eventlogger.features.learnonboarding.c
            long r7 = r4.f
            r9 = 0
            r6.<init>(r9, r7, r3)
            r5.getClass()
            java.lang.String r3 = "study_paths_intake_screen_load"
            com.quizlet.eventlogger.features.learnonboarding.LearnOnboardingEventLog r3 = com.quizlet.eventlogger.features.learnonboarding.LearnOnboardingEventLog.Companion.a(r3, r6)
            r1.a(r3)
            r11.j = r2
            kotlinx.coroutines.flow.s0 r1 = r4.m
            r1.l(r12)
            kotlin.Unit r12 = kotlin.Unit.a
            if (r12 != r0) goto L6f
        L6e:
            return r0
        L6f:
            kotlin.Unit r12 = kotlin.Unit.a
            return r12
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.learn.viewmodel.C4559f.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}

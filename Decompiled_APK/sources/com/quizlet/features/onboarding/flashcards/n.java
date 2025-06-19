package com.quizlet.features.onboarding.flashcards;

import androidx.lifecycle.w0;
import com.quizlet.eventlogger.model.OnboardingFlashcardsEventLog;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.flow.d0;
import kotlinx.coroutines.flow.e0;

@Metadata
/* loaded from: classes3.dex */
public final class n extends w0 {
    public final long b;
    public final j c;
    public final com.google.mlkit.vision.documentscanner.internal.c d;
    public final d0 e;

    public n(long j, j onboardingFlashcardsLogger, com.google.mlkit.vision.documentscanner.internal.c onBoardingFlashcardsPreferences) {
        Intrinsics.checkNotNullParameter(onboardingFlashcardsLogger, "onboardingFlashcardsLogger");
        Intrinsics.checkNotNullParameter(onBoardingFlashcardsPreferences, "onBoardingFlashcardsPreferences");
        this.b = j;
        this.c = onboardingFlashcardsLogger;
        this.d = onBoardingFlashcardsPreferences;
        this.e = e0.b(0, 0, null, 7);
        OnboardingFlashcardsEventLog.b.getClass();
        Intrinsics.checkNotNullParameter("onboarding_flashcards_screen_view", "action");
        OnboardingFlashcardsEventLog onboardingFlashcardsEventLog = new OnboardingFlashcardsEventLog(new OnboardingFlashcardsEventLog.Payload(null, 1, null));
        onboardingFlashcardsEventLog.setAction("onboarding_flashcards_screen_view");
        onboardingFlashcardsLogger.a.l(onboardingFlashcardsEventLog);
    }

    /* JADX WARN: Code restructure failed: missing block: B:23:0x0087, code lost:
    
        if (r8.emit(r9, r0) == r1) goto L24;
     */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0016  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object A(com.quizlet.features.onboarding.flashcards.n r8, kotlin.coroutines.jvm.internal.c r9) {
        /*
            r8.getClass()
            boolean r0 = r9 instanceof com.quizlet.features.onboarding.flashcards.k
            if (r0 == 0) goto L16
            r0 = r9
            com.quizlet.features.onboarding.flashcards.k r0 = (com.quizlet.features.onboarding.flashcards.k) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L16
            int r1 = r1 - r2
            r0.m = r1
            goto L1b
        L16:
            com.quizlet.features.onboarding.flashcards.k r0 = new com.quizlet.features.onboarding.flashcards.k
            r0.<init>(r8, r9)
        L1b:
            java.lang.Object r9 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 0
            r4 = 2
            r5 = 1
            if (r2 == 0) goto L3c
            if (r2 == r5) goto L36
            if (r2 != r4) goto L2e
            androidx.glance.appwidget.protobuf.Z.e(r9)
            goto L8a
        L2e:
            java.lang.IllegalStateException r8 = new java.lang.IllegalStateException
            java.lang.String r9 = "call to 'resume' before 'invoke' with coroutine"
            r8.<init>(r9)
            throw r8
        L36:
            com.quizlet.features.onboarding.flashcards.n r8 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r9)
            goto L7b
        L3c:
            androidx.glance.appwidget.protobuf.Z.e(r9)
            r0.j = r8
            r0.m = r5
            com.google.mlkit.vision.documentscanner.internal.c r9 = r8.d
            r9.getClass()
            java.lang.Long r2 = new java.lang.Long
            long r6 = r8.b
            r2.<init>(r6)
            java.lang.Object[] r2 = new java.lang.Object[]{r2}
            java.lang.Object[] r2 = java.util.Arrays.copyOf(r2, r5)
            java.lang.String r5 = "user_completed_onboarding_flashcards_%s"
            java.lang.String r2 = java.lang.String.format(r5, r2)
            java.lang.String r5 = "format(...)"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r2, r5)
            androidx.datastore.preferences.core.f r2 = com.google.android.gms.internal.mlkit_vision_barcode.R6.a(r2)
            com.quizlet.local.datastore.preferences.f0 r5 = new com.quizlet.local.datastore.preferences.f0
            r5.<init>(r2, r3)
            java.lang.Object r9 = r9.b
            androidx.datastore.core.h r9 = (androidx.datastore.core.InterfaceC1076h) r9
            java.lang.Object r9 = com.google.android.gms.internal.mlkit_vision_barcode.S6.d(r9, r5, r0)
            if (r9 != r1) goto L76
            goto L78
        L76:
            kotlin.Unit r9 = kotlin.Unit.a
        L78:
            if (r9 != r1) goto L7b
            goto L89
        L7b:
            kotlinx.coroutines.flow.d0 r8 = r8.e
            kotlin.Unit r9 = kotlin.Unit.a
            r0.j = r3
            r0.m = r4
            java.lang.Object r8 = r8.emit(r9, r0)
            if (r8 != r1) goto L8a
        L89:
            return r1
        L8a:
            kotlin.Unit r8 = kotlin.Unit.a
            return r8
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.onboarding.flashcards.n.A(com.quizlet.features.onboarding.flashcards.n, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }
}

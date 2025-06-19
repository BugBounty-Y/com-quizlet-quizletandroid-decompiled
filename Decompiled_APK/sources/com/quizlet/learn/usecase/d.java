package com.quizlet.learn.usecase;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class d {
    public final b a;
    public final assistantMode.utils.studiableMetadata.b b;

    public d(b getLongTextSmartGradingFeatureEnabledUseCase, assistantMode.utils.studiableMetadata.b getTypoHelpEligibleUseCase) {
        Intrinsics.checkNotNullParameter(getLongTextSmartGradingFeatureEnabledUseCase, "getLongTextSmartGradingFeatureEnabledUseCase");
        Intrinsics.checkNotNullParameter(getTypoHelpEligibleUseCase, "getTypoHelpEligibleUseCase");
        this.a = getLongTextSmartGradingFeatureEnabledUseCase;
        this.b = getTypoHelpEligibleUseCase;
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object a(long r5, java.lang.String r7, java.lang.String r8, com.quizlet.infra.legacysyncengine.features.properties.d r9, kotlin.coroutines.jvm.internal.c r10) {
        /*
            r4 = this;
            boolean r0 = r10 instanceof com.quizlet.learn.usecase.c
            if (r0 == 0) goto L13
            r0 = r10
            com.quizlet.learn.usecase.c r0 = (com.quizlet.learn.usecase.c) r0
            int r1 = r0.o
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.o = r1
            goto L18
        L13:
            com.quizlet.learn.usecase.c r0 = new com.quizlet.learn.usecase.c
            r0.<init>(r4, r10)
        L18:
            java.lang.Object r10 = r0.m
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.o
            r3 = 1
            if (r2 == 0) goto L35
            if (r2 != r3) goto L2d
            java.lang.String r8 = r0.l
            java.lang.String r7 = r0.k
            com.quizlet.learn.usecase.d r5 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r10)
            goto L4a
        L2d:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L35:
            androidx.glance.appwidget.protobuf.Z.e(r10)
            r0.j = r4
            r0.k = r7
            r0.l = r8
            r0.o = r3
            com.quizlet.learn.usecase.b r10 = r4.a
            java.lang.Object r10 = r10.a(r5, r9, r0)
            if (r10 != r1) goto L49
            return r1
        L49:
            r5 = r4
        L4a:
            java.lang.Boolean r10 = (java.lang.Boolean) r10
            boolean r6 = r10.booleanValue()
            assistantMode.utils.studiableMetadata.b r5 = r5.b
            boolean r5 = kotlin.jvm.internal.Intrinsics.b(r7, r8)
            r8 = 0
            if (r5 == 0) goto L64
            if (r7 != 0) goto L5c
            goto L64
        L5c:
            java.util.List r5 = com.quizlet.generated.sharedconfig.c.c
            boolean r5 = r5.contains(r7)
            if (r5 == 0) goto L65
        L64:
            r3 = r8
        L65:
            java.util.LinkedHashSet r5 = new java.util.LinkedHashSet
            r5.<init>()
            if (r3 == 0) goto L71
            com.quizlet.learn.settings.data.WrittenQuestionGradingOption$Moderate r7 = com.quizlet.learn.settings.data.WrittenQuestionGradingOption.Moderate.e
            r5.add(r7)
        L71:
            if (r6 == 0) goto L78
            com.quizlet.learn.settings.data.WrittenQuestionGradingOption$Relaxed r6 = com.quizlet.learn.settings.data.WrittenQuestionGradingOption.Relaxed.e
            r5.add(r6)
        L78:
            com.quizlet.learn.settings.data.WrittenQuestionGradingOption$Strict r6 = com.quizlet.learn.settings.data.WrittenQuestionGradingOption.Strict.e
            r5.add(r6)
            kotlinx.collections.immutable.c r5 = com.google.android.gms.internal.mlkit_vision_camera.AbstractC3409x1.j(r5)
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.learn.usecase.d.a(long, java.lang.String, java.lang.String, com.quizlet.infra.legacysyncengine.features.properties.d, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }
}

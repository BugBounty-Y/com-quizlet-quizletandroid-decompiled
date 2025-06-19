package com.quizlet.features.onboarding.survey;

import com.quizlet.local.datastore.preferences.n0;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.AbstractC5040y;

/* loaded from: classes3.dex */
public final class j {
    public final com.quizlet.data.repository.user.a a;
    public final n0 b;

    public j(AbstractC5040y dispatcher, com.quizlet.data.repository.user.a onboardingSurveyFeature, n0 onboardingSurveyPreferences) {
        com.quizlet.time.b timeProvider = com.quizlet.time.b.a;
        Intrinsics.checkNotNullParameter(dispatcher, "dispatcher");
        Intrinsics.checkNotNullParameter(onboardingSurveyFeature, "onboardingSurveyFeature");
        Intrinsics.checkNotNullParameter(onboardingSurveyPreferences, "onboardingSurveyPreferences");
        Intrinsics.checkNotNullParameter(timeProvider, "timeProvider");
        this.a = onboardingSurveyFeature;
        this.b = onboardingSurveyPreferences;
    }

    /* JADX WARN: Code restructure failed: missing block: B:36:0x00b4, code lost:
    
        if (r11 != r1) goto L38;
     */
    /* JADX WARN: Removed duplicated region for block: B:31:0x008b  */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object a(androidx.work.impl.model.c r10, kotlin.coroutines.jvm.internal.c r11) {
        /*
            r9 = this;
            boolean r0 = r11 instanceof com.quizlet.features.onboarding.survey.i
            if (r0 == 0) goto L13
            r0 = r11
            com.quizlet.features.onboarding.survey.i r0 = (com.quizlet.features.onboarding.survey.i) r0
            int r1 = r0.n
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.n = r1
            goto L18
        L13:
            com.quizlet.features.onboarding.survey.i r0 = new com.quizlet.features.onboarding.survey.i
            r0.<init>(r9, r11)
        L18:
            java.lang.Object r11 = r0.l
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.n
            r3 = 0
            r4 = 4
            r5 = 3
            r6 = 2
            r7 = 1
            if (r2 == 0) goto L56
            if (r2 == r7) goto L4c
            if (r2 == r6) goto L42
            if (r2 == r5) goto L3a
            if (r2 != r4) goto L32
            androidx.glance.appwidget.protobuf.Z.e(r11)
            goto Lb7
        L32:
            java.lang.IllegalStateException r10 = new java.lang.IllegalStateException
            java.lang.String r11 = "call to 'resume' before 'invoke' with coroutine"
            r10.<init>(r11)
            throw r10
        L3a:
            java.lang.Object r10 = r0.j
            com.quizlet.local.datastore.preferences.n0 r10 = (com.quizlet.local.datastore.preferences.n0) r10
            androidx.glance.appwidget.protobuf.Z.e(r11)
            goto La1
        L42:
            androidx.work.impl.model.c r10 = r0.k
            java.lang.Object r2 = r0.j
            com.quizlet.features.onboarding.survey.j r2 = (com.quizlet.features.onboarding.survey.j) r2
            androidx.glance.appwidget.protobuf.Z.e(r11)
            goto L83
        L4c:
            androidx.work.impl.model.c r10 = r0.k
            java.lang.Object r2 = r0.j
            com.quizlet.features.onboarding.survey.j r2 = (com.quizlet.features.onboarding.survey.j) r2
            androidx.glance.appwidget.protobuf.Z.e(r11)
            goto L69
        L56:
            androidx.glance.appwidget.protobuf.Z.e(r11)
            r0.j = r9
            r0.k = r10
            r0.n = r7
            com.quizlet.data.repository.user.a r11 = r9.a
            java.lang.Object r11 = r11.j(r0)
            if (r11 != r1) goto L68
            goto Lb6
        L68:
            r2 = r9
        L69:
            java.lang.Boolean r11 = (java.lang.Boolean) r11
            boolean r11 = r11.booleanValue()
            if (r11 == 0) goto Lc0
            r2.getClass()
            com.quizlet.time.b r11 = com.quizlet.time.b.a
            r0.j = r2
            r0.k = r10
            r0.n = r6
            java.lang.Object r11 = com.google.android.gms.internal.mlkit_vision_camera.J1.b(r10, r11, r0)
            if (r11 != r1) goto L83
            goto Lb6
        L83:
            java.lang.Boolean r11 = (java.lang.Boolean) r11
            boolean r11 = r11.booleanValue()
            if (r11 == 0) goto Lc0
            com.quizlet.local.datastore.preferences.n0 r11 = r2.b
            io.reactivex.rxjava3.internal.operators.single.g r10 = r10.n()
            r0.j = r11
            r0.k = r3
            r0.n = r5
            java.lang.Object r10 = com.google.android.gms.internal.mlkit_vision_camera.I1.b(r10, r0)
            if (r10 != r1) goto L9e
            goto Lb6
        L9e:
            r8 = r11
            r11 = r10
            r10 = r8
        La1:
            java.lang.String r2 = "await(...)"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r11, r2)
            java.lang.Number r11 = (java.lang.Number) r11
            long r5 = r11.longValue()
            r0.j = r3
            r0.n = r4
            java.lang.Object r11 = r10.a(r5, r0)
            if (r11 != r1) goto Lb7
        Lb6:
            return r1
        Lb7:
            java.lang.Boolean r11 = (java.lang.Boolean) r11
            boolean r10 = r11.booleanValue()
            if (r10 != 0) goto Lc0
            goto Lc1
        Lc0:
            r7 = 0
        Lc1:
            java.lang.Boolean r10 = java.lang.Boolean.valueOf(r7)
            return r10
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.onboarding.survey.j.a(androidx.work.impl.model.c, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }
}

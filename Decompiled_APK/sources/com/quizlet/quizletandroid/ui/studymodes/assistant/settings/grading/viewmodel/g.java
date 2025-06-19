package com.quizlet.quizletandroid.ui.studymodes.assistant.settings.grading.viewmodel;

import androidx.lifecycle.m0;
import androidx.lifecycle.p0;
import androidx.lifecycle.w0;
import com.onetrust.otpublishers.headless.UI.fragment.q;
import com.quizlet.quizletandroid.ui.studymodes.assistant.settings.grading.data.h;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.AbstractC5040y;
import kotlinx.coroutines.E;
import kotlinx.coroutines.flow.d0;
import kotlinx.coroutines.flow.e0;
import kotlinx.coroutines.flow.s0;

@Metadata
/* loaded from: classes3.dex */
public final class g extends w0 implements a {
    public final com.quizlet.infra.legacysyncengine.features.properties.d b;
    public final AbstractC5040y c;
    public final q d;
    public final androidx.work.impl.model.c e;
    public final com.quizlet.data.repository.course.membership.c f;
    public final com.quizlet.learn.usecase.b g;
    public final s0 h;
    public final d0 i;
    public final com.quizlet.features.infra.basestudy.manager.f j;

    public g(m0 savedStateHandle, com.quizlet.features.infra.basestudy.manager.a studyModeManagerFactory, com.quizlet.infra.legacysyncengine.features.properties.d studySetProperties, AbstractC5040y ioDispatcher, q surveyFeature, androidx.work.impl.model.c userProperties, com.quizlet.data.repository.course.membership.c saveLearnSettingsGradingUseCase, com.quizlet.learn.usecase.b getLongTextSmartGradingFeatureEnabledUseCase) {
        Intrinsics.checkNotNullParameter(savedStateHandle, "savedStateHandle");
        Intrinsics.checkNotNullParameter(studyModeManagerFactory, "studyModeManagerFactory");
        Intrinsics.checkNotNullParameter(studySetProperties, "studySetProperties");
        Intrinsics.checkNotNullParameter(ioDispatcher, "ioDispatcher");
        Intrinsics.checkNotNullParameter(surveyFeature, "surveyFeature");
        Intrinsics.checkNotNullParameter(userProperties, "userProperties");
        Intrinsics.checkNotNullParameter(saveLearnSettingsGradingUseCase, "saveLearnSettingsGradingUseCase");
        Intrinsics.checkNotNullParameter(getLongTextSmartGradingFeatureEnabledUseCase, "getLongTextSmartGradingFeatureEnabledUseCase");
        this.b = studySetProperties;
        this.c = ioDispatcher;
        this.d = surveyFeature;
        this.e = userProperties;
        this.f = saveLearnSettingsGradingUseCase;
        this.g = getLongTextSmartGradingFeatureEnabledUseCase;
        this.h = e0.c(h.a);
        this.i = e0.b(0, 1, null, 5);
        this.j = studyModeManagerFactory.a(savedStateHandle);
        E.A(p0.j(this), null, null, new b(this, null), 3);
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0016  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object A(com.quizlet.quizletandroid.ui.studymodes.assistant.settings.grading.viewmodel.g r9, com.quizlet.features.infra.studysetting.data.QuestionSettings r10, kotlin.coroutines.jvm.internal.c r11) {
        /*
            r9.getClass()
            boolean r0 = r11 instanceof com.quizlet.quizletandroid.ui.studymodes.assistant.settings.grading.viewmodel.f
            if (r0 == 0) goto L16
            r0 = r11
            com.quizlet.quizletandroid.ui.studymodes.assistant.settings.grading.viewmodel.f r0 = (com.quizlet.quizletandroid.ui.studymodes.assistant.settings.grading.viewmodel.f) r0
            int r1 = r0.o
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L16
            int r1 = r1 - r2
            r0.o = r1
            goto L1b
        L16:
            com.quizlet.quizletandroid.ui.studymodes.assistant.settings.grading.viewmodel.f r0 = new com.quizlet.quizletandroid.ui.studymodes.assistant.settings.grading.viewmodel.f
            r0.<init>(r9, r11)
        L1b:
            java.lang.Object r11 = r0.m
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.o
            r3 = 1
            r4 = 2
            if (r2 == 0) goto L44
            if (r2 == r3) goto L3c
            if (r2 != r4) goto L34
            boolean r9 = r0.l
            com.quizlet.features.infra.studysetting.data.QuestionSettings r10 = r0.k
            com.quizlet.quizletandroid.ui.studymodes.assistant.settings.grading.viewmodel.g r0 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r11)
            r6 = r9
            goto L9b
        L34:
            java.lang.IllegalStateException r9 = new java.lang.IllegalStateException
            java.lang.String r10 = "call to 'resume' before 'invoke' with coroutine"
            r9.<init>(r10)
            throw r9
        L3c:
            com.quizlet.features.infra.studysetting.data.QuestionSettings r10 = r0.k
            com.quizlet.quizletandroid.ui.studymodes.assistant.settings.grading.viewmodel.g r9 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r11)
            goto L7b
        L44:
            androidx.glance.appwidget.protobuf.Z.e(r11)
            r0.j = r9
            r0.k = r10
            r0.o = r3
            com.quizlet.infra.legacysyncengine.features.properties.d r11 = r9.b
            com.onetrust.otpublishers.headless.UI.fragment.q r2 = r9.d
            androidx.work.impl.model.c r3 = r9.e
            r2.getClass()
            java.lang.String r5 = "userProps"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r3, r5)
            java.lang.String r5 = "contentProps"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r11, r5)
            io.reactivex.rxjava3.internal.operators.single.g r5 = r3.u()
            io.reactivex.rxjava3.internal.operators.single.g r5 = com.google.android.gms.dynamite.d.e(r5)
            java.lang.Object r2 = r2.b
            com.quizlet.featuregate.features.flexiblegrading.a r2 = (com.quizlet.featuregate.features.flexiblegrading.a) r2
            io.reactivex.rxjava3.internal.operators.single.g r11 = r2.b(r3, r11)
            io.reactivex.rxjava3.internal.operators.single.g r11 = com.google.android.gms.dynamite.d.b(r5, r11)
            java.lang.Object r11 = com.google.android.gms.internal.mlkit_vision_camera.I1.b(r11, r0)
            if (r11 != r1) goto L7b
            goto L97
        L7b:
            java.lang.Boolean r11 = (java.lang.Boolean) r11
            boolean r11 = r11.booleanValue()
            com.quizlet.learn.usecase.b r2 = r9.g
            com.quizlet.features.infra.basestudy.manager.f r3 = r9.j
            long r5 = r3.u
            r0.j = r9
            r0.k = r10
            r0.l = r11
            r0.o = r4
            com.quizlet.infra.legacysyncengine.features.properties.d r3 = r9.b
            java.lang.Object r0 = r2.a(r5, r3, r0)
            if (r0 != r1) goto L98
        L97:
            return r1
        L98:
            r6 = r11
            r11 = r0
            r0 = r9
        L9b:
            java.lang.Boolean r11 = (java.lang.Boolean) r11
            boolean r7 = r11.booleanValue()
            kotlinx.coroutines.flow.s0 r9 = r0.h
        La3:
            java.lang.Object r11 = r9.getValue()
            r0 = r11
            com.quizlet.quizletandroid.ui.studymodes.assistant.settings.grading.data.i r0 = (com.quizlet.quizletandroid.ui.studymodes.assistant.settings.grading.data.i) r0
            com.quizlet.quizletandroid.ui.studymodes.assistant.settings.grading.data.g r2 = new com.quizlet.quizletandroid.ui.studymodes.assistant.settings.grading.data.g
            boolean r3 = r10.p
            r8 = r7 ^ 1
            boolean r5 = r10.o
            boolean r4 = r10.n
            r2.<init>(r3, r4, r5, r6, r7, r8)
            boolean r11 = r9.k(r11, r2)
            if (r11 == 0) goto La3
            kotlin.Unit r9 = kotlin.Unit.a
            return r9
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.quizletandroid.ui.studymodes.assistant.settings.grading.viewmodel.g.A(com.quizlet.quizletandroid.ui.studymodes.assistant.settings.grading.viewmodel.g, com.quizlet.features.infra.studysetting.data.QuestionSettings, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }
}

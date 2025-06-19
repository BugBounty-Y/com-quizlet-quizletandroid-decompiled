package com.quizlet.features.infra.basestudy.usecase;

import com.quizlet.data.repository.studysetwithcreatorinclass.g;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class b {
    public final g a;
    public final com.google.firebase.perf.logging.b b;
    public final androidx.work.impl.model.c c;
    public final com.quizlet.data.interactor.metering.b d;
    public final com.quizlet.infra.legacysyncengine.managers.d e;

    public b(g studySettingManagerFactory, com.google.firebase.perf.logging.b studyPathFeature, androidx.work.impl.model.c userProperties, com.quizlet.data.interactor.metering.b getMeteringInfoUseCase, com.quizlet.infra.legacysyncengine.managers.d loggedInUserManager) {
        Intrinsics.checkNotNullParameter(studySettingManagerFactory, "studySettingManagerFactory");
        Intrinsics.checkNotNullParameter(studyPathFeature, "studyPathFeature");
        Intrinsics.checkNotNullParameter(userProperties, "userProperties");
        Intrinsics.checkNotNullParameter(getMeteringInfoUseCase, "getMeteringInfoUseCase");
        Intrinsics.checkNotNullParameter(loggedInUserManager, "loggedInUserManager");
        this.a = studySettingManagerFactory;
        this.b = studyPathFeature;
        this.c = userProperties;
        this.d = getMeteringInfoUseCase;
        this.e = loggedInUserManager;
    }

    /* JADX WARN: Removed duplicated region for block: B:35:0x01a8  */
    /* JADX WARN: Removed duplicated region for block: B:39:0x01d1  */
    /* JADX WARN: Removed duplicated region for block: B:8:0x0018  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object a(com.quizlet.features.infra.models.studymodeshared.StudyableModelData r22, long r23, boolean r25, kotlin.coroutines.jvm.internal.c r26) {
        /*
            Method dump skipped, instructions count: 506
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.infra.basestudy.usecase.b.a(com.quizlet.features.infra.models.studymodeshared.StudyableModelData, long, boolean, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }
}

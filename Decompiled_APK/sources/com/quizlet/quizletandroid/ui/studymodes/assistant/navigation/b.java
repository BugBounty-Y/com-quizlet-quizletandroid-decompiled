package com.quizlet.quizletandroid.ui.studymodes.assistant.navigation;

import android.content.Context;
import com.quizlet.features.infra.navigation.k;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class b implements k {
    public final Context a;
    public final com.quizlet.features.infra.basestudy.usecase.b b;

    public b(Context context, com.quizlet.features.infra.basestudy.usecase.b getLearnNavigationUseCase) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(getLearnNavigationUseCase, "getLearnNavigationUseCase");
        this.a = context;
        this.b = getLearnNavigationUseCase;
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:8:0x0016  */
    /* JADX WARN: Type inference failed for: r2v3, types: [com.quizlet.features.infra.models.studymodeshared.StudyableModelData] */
    @Override // com.quizlet.features.infra.navigation.k
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object a(com.quizlet.features.infra.models.studymodeshared.StudyableModelData.StudyFolder r14, java.lang.String r15, long r16, kotlin.coroutines.h r18) {
        /*
            r13 = this;
            r0 = r18
            boolean r1 = r0 instanceof com.quizlet.quizletandroid.ui.studymodes.assistant.navigation.a
            if (r1 == 0) goto L16
            r1 = r0
            com.quizlet.quizletandroid.ui.studymodes.assistant.navigation.a r1 = (com.quizlet.quizletandroid.ui.studymodes.assistant.navigation.a) r1
            int r2 = r1.p
            r3 = -2147483648(0xffffffff80000000, float:-0.0)
            r4 = r2 & r3
            if (r4 == 0) goto L16
            int r2 = r2 - r3
            r1.p = r2
        L14:
            r7 = r1
            goto L1e
        L16:
            com.quizlet.quizletandroid.ui.studymodes.assistant.navigation.a r1 = new com.quizlet.quizletandroid.ui.studymodes.assistant.navigation.a
            kotlin.coroutines.jvm.internal.c r0 = (kotlin.coroutines.jvm.internal.c) r0
            r1.<init>(r13, r0)
            goto L14
        L1e:
            java.lang.Object r0 = r7.n
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r7.p
            r3 = 1
            if (r2 == 0) goto L41
            if (r2 != r3) goto L39
            long r14 = r7.m
            java.lang.String r1 = r7.l
            com.quizlet.features.infra.models.studymodeshared.StudyableModelData r2 = r7.k
            com.quizlet.quizletandroid.ui.studymodes.assistant.navigation.b r3 = r7.j
            androidx.glance.appwidget.protobuf.Z.e(r0)
            r6 = r14
            r5 = r1
            r4 = r2
            r14 = r3
            goto L61
        L39:
            java.lang.IllegalStateException r14 = new java.lang.IllegalStateException
            java.lang.String r15 = "call to 'resume' before 'invoke' with coroutine"
            r14.<init>(r15)
            throw r14
        L41:
            androidx.glance.appwidget.protobuf.Z.e(r0)
            r7.j = r13
            r7.k = r14
            r7.l = r15
            r8 = r16
            r7.m = r8
            r7.p = r3
            com.quizlet.features.infra.basestudy.usecase.b r2 = r13.b
            r4 = -1
            r6 = 0
            r3 = r14
            java.lang.Object r0 = r2.a(r3, r4, r6, r7)
            if (r0 != r1) goto L5d
            return r1
        L5d:
            r4 = r14
            r5 = r15
            r6 = r8
            r14 = r13
        L61:
            com.quizlet.features.infra.basestudy.usecase.e r0 = (com.quizlet.features.infra.basestudy.usecase.e) r0
            java.lang.String r15 = com.quizlet.quizletandroid.ui.studymodes.assistant.LearningAssistantActivity.D
            android.content.Context r2 = r14.a
            com.quizlet.data.model.w0 r11 = r0.a
            boolean r12 = r0.b
            r3 = 0
            r8 = 0
            r9 = 0
            r10 = 0
            android.content.Intent r15 = com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3675m6.b(r2, r3, r4, r5, r6, r8, r9, r10, r11, r12)
            android.content.Context r14 = r14.a
            r14.startActivity(r15)
            kotlin.Unit r14 = kotlin.Unit.a
            return r14
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.quizletandroid.ui.studymodes.assistant.navigation.b.a(com.quizlet.features.infra.models.studymodeshared.StudyableModelData$StudyFolder, java.lang.String, long, kotlin.coroutines.h):java.lang.Object");
    }
}

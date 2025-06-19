package com.quizlet.features.practicetest.navigation;

import android.content.Context;
import com.google.android.gms.internal.mlkit_vision_camera.L1;
import com.quizlet.data.model.U0;
import com.quizlet.features.infra.navigation.r;
import com.quizlet.features.practicetest.PracticeTestActivity;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes3.dex */
public final class j implements r {
    public final Context a;

    public j(@NotNull Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        this.a = context;
    }

    @Override // com.quizlet.features.infra.navigation.r
    public final void g(String questionBankUuid) {
        U0 origin = U0.e;
        Intrinsics.checkNotNullParameter(questionBankUuid, "questionBankUuid");
        Intrinsics.checkNotNullParameter(origin, "origin");
        int i = PracticeTestActivity.h;
        Context context = this.a;
        context.startActivity(L1.d(context, questionBankUuid, origin));
    }

    @Override // com.quizlet.features.infra.navigation.r
    public final void k(String questionBankUuid) {
        Intrinsics.checkNotNullParameter(questionBankUuid, "questionBankUuid");
        int i = PracticeTestActivity.h;
        Context context = this.a;
        context.startActivity(L1.c(context, questionBankUuid));
    }
}

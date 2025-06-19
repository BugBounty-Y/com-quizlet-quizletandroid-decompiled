package com.quizlet.analytics.marketing.appsflyer;

import android.content.Context;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class b {
    public final Context a;
    public final com.quizlet.data.repository.folderwithcreatorinclass.e b;

    public b(Context context, com.quizlet.data.repository.folderwithcreatorinclass.e qIncentivesUseCase) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(qIncentivesUseCase, "qIncentivesUseCase");
        this.a = context;
        this.b = qIncentivesUseCase;
    }
}

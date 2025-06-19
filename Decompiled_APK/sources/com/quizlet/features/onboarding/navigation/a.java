package com.quizlet.features.onboarding.navigation;

import android.content.Context;
import android.content.Intent;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes3.dex */
public final class a implements com.quizlet.features.infra.navigation.p {
    public final Context a;

    public a(@NotNull Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        this.a = context;
    }

    @Override // com.quizlet.features.infra.navigation.p
    public final void c(androidx.activity.result.b launcher) {
        Intrinsics.checkNotNullParameter(launcher, "launcher");
        int i = OnboardingNavigationActivity.j;
        Context context = this.a;
        Intrinsics.checkNotNullParameter(context, "context");
        launcher.a(new Intent(context, (Class<?>) OnboardingNavigationActivity.class));
    }
}

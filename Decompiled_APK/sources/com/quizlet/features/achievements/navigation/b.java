package com.quizlet.features.achievements.navigation;

import android.content.Context;
import android.content.Intent;
import com.quizlet.features.achievements.ui.AchievementsActivity;
import com.quizlet.features.infra.navigation.InterfaceC4341a;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes2.dex */
public final class b implements InterfaceC4341a {
    public final Context a;

    public b(@NotNull Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        this.a = context;
    }

    @Override // com.quizlet.features.infra.navigation.InterfaceC4341a
    public final void e() {
        String str = AchievementsActivity.i;
        Context context = this.a;
        Intrinsics.checkNotNullParameter(context, "context");
        context.startActivity(new Intent(context, (Class<?>) AchievementsActivity.class));
    }
}

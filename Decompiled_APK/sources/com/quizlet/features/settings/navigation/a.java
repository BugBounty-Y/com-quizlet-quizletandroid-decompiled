package com.quizlet.features.settings.navigation;

import android.content.Context;
import com.google.android.gms.internal.mlkit_vision_common.C2;
import com.quizlet.features.infra.navigation.v;
import com.quizlet.features.settings.SettingsActivity;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes3.dex */
public final class a implements v {
    public final Context a;

    public a(@NotNull Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        this.a = context;
    }

    @Override // com.quizlet.features.infra.navigation.v
    public final void b() {
        int i = SettingsActivity.p;
        Context context = this.a;
        context.startActivity(C2.c(context));
    }
}

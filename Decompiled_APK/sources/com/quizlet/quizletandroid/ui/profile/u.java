package com.quizlet.quizletandroid.ui.profile;

import android.content.Context;
import com.quizlet.features.infra.navigation.C;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes3.dex */
public final class u implements C {
    public final Context a;

    public u(@NotNull Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        this.a = context;
    }

    @Override // com.quizlet.features.infra.navigation.C
    public final void y(long j) {
        b bVar = ProfileActivity.p;
        Context context = this.a;
        context.startActivity(bVar.g(context, j));
    }
}

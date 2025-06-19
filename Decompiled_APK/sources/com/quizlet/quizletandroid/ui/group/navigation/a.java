package com.quizlet.quizletandroid.ui.group.navigation;

import android.content.Context;
import com.quizlet.features.infra.navigation.s;
import com.quizlet.quizletandroid.ui.group.GroupActivity;
import com.quizlet.quizletandroid.ui.group.f;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes3.dex */
public final class a implements s {
    public final Context a;

    public a(@NotNull Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        this.a = context;
    }

    @Override // com.quizlet.features.infra.navigation.s
    public final void F(long j) {
        String str = GroupActivity.u;
        Long lValueOf = Long.valueOf(j);
        Context context = this.a;
        context.startActivity(f.a(context, lValueOf, null, false, null));
    }
}

package com.quizlet.features.setpage.navigation;

import android.content.Context;
import com.quizlet.features.infra.navigation.i;
import com.quizlet.features.setpage.SetPageActivity;
import com.quizlet.features.setpage.e;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes3.dex */
public final class a implements i {
    public final Context a;

    public a(@NotNull Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        this.a = context;
    }

    @Override // com.quizlet.features.infra.navigation.i
    public final void z(long j) {
        this.a.startActivity(e.b(SetPageActivity.h1, this.a, j, null, null, null, null, false, null, 252));
    }
}

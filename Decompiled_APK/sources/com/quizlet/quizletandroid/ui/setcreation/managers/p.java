package com.quizlet.quizletandroid.ui.setcreation.managers;

import android.content.Context;
import android.content.SharedPreferences;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes3.dex */
public final class p {
    public final SharedPreferences a;

    public p(@NotNull Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        this.a = context.getSharedPreferences("draft_set_edit_tracker", 0);
    }
}

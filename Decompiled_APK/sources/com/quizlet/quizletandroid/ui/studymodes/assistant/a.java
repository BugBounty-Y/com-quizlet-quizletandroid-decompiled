package com.quizlet.quizletandroid.ui.studymodes.assistant;

import android.content.Context;
import android.content.SharedPreferences;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes3.dex */
public final class a {
    public final SharedPreferences a;

    public a(@NotNull Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        this.a = context.getSharedPreferences("aprt_prefs", 0);
    }
}

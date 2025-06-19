package com.quizlet.quizletandroid.lib;

import android.content.Context;
import android.content.SharedPreferences;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes3.dex */
public final class c {
    public final SharedPreferences a;

    public c(@NotNull Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        this.a = context.getSharedPreferences("PREFS_GA_LOGGING", 0);
    }
}

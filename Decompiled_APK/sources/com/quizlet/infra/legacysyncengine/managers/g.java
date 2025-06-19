package com.quizlet.infra.legacysyncengine.managers;

import android.content.Context;
import android.content.SharedPreferences;
import androidx.compose.animation.d0;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes3.dex */
public final class g {
    public final SharedPreferences a;

    public g(@NotNull Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        SharedPreferences sharedPreferences = context.getSharedPreferences("QuizletLiveSharedPreferences", 0);
        Intrinsics.checkNotNullExpressionValue(sharedPreferences, "getSharedPreferences(...)");
        this.a = sharedPreferences;
    }

    public final f a(long j) {
        return this.a.getInt(d0.s(new Object[]{Long.valueOf(j)}, 1, "user_preferred_join_method_%s", "format(...)"), 0) == 1 ? f.b : f.c;
    }
}

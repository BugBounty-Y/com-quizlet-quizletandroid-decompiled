package com.quizlet.quizletandroid.ui.activitycenter.managers;

import android.content.SharedPreferences;
import java.util.concurrent.TimeUnit;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class b {
    public static final long b = TimeUnit.DAYS.toMillis(1);
    public final SharedPreferences a;

    public b(SharedPreferences sharedPreferences) {
        Intrinsics.checkNotNullParameter(sharedPreferences, "sharedPreferences");
        this.a = sharedPreferences;
    }
}

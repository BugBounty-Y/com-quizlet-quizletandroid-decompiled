package com.quizlet.ads;

import android.content.SharedPreferences;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class d {
    public final long a;
    public final SharedPreferences b;

    public d(long j, SharedPreferences sharedPreferences) {
        Intrinsics.checkNotNullParameter(sharedPreferences, "sharedPreferences");
        this.a = j;
        this.b = sharedPreferences;
    }

    public d(SharedPreferences sharedPreferences, long j) {
        Intrinsics.checkNotNullParameter(sharedPreferences, "sharedPreferences");
        this.b = sharedPreferences;
        this.a = j;
    }
}

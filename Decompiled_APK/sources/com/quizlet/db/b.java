package com.quizlet.db;

import android.content.SharedPreferences;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class b {
    public final SharedPreferences a;

    public b(SharedPreferences sharedPreferences, int i) {
        switch (i) {
            case 1:
                Intrinsics.checkNotNullParameter(sharedPreferences, "sharedPreferences");
                this.a = sharedPreferences;
                break;
            case 2:
                Intrinsics.checkNotNullParameter(sharedPreferences, "sharedPreferences");
                this.a = sharedPreferences;
                break;
            default:
                Intrinsics.checkNotNullParameter(sharedPreferences, "sharedPreferences");
                this.a = sharedPreferences;
                break;
        }
    }
}

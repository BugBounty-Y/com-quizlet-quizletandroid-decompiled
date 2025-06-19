package com.quizlet.features.setpage.upsell;

import android.content.SharedPreferences;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a {
    public final SharedPreferences a;

    public a(SharedPreferences sharedPreferences, int i) {
        switch (i) {
            case 1:
                Intrinsics.checkNotNullParameter(sharedPreferences, "sharedPreferences");
                this.a = sharedPreferences;
                break;
            default:
                com.quizlet.time.b timeProvider = com.quizlet.time.b.a;
                Intrinsics.checkNotNullParameter(sharedPreferences, "sharedPreferences");
                Intrinsics.checkNotNullParameter(timeProvider, "timeProvider");
                this.a = sharedPreferences;
                break;
        }
    }
}

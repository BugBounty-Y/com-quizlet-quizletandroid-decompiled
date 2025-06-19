package com.quizlet.quizletandroid.ui.promo.engine;

import android.content.Context;
import android.content.SharedPreferences;
import androidx.annotation.NonNull;

/* loaded from: classes3.dex */
public class a {
    public final SharedPreferences a;

    public a(@NonNull Context context) {
        this.a = context.getSharedPreferences("PREFS_PROMO_ENGINE", 0);
    }
}

package com.quizlet.features.infra.basestudy.data.models.onboarding;

import android.content.Context;
import android.content.SharedPreferences;

/* loaded from: classes3.dex */
public class a {
    public final SharedPreferences a;

    public a(Context context) {
        this.a = context.getSharedPreferences("PREFS_ASSISTANT_ONBOARDING", 0);
    }
}

package com.quizlet.db.token;

import android.content.SharedPreferences;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class b implements a {
    public final SharedPreferences a;

    public b(SharedPreferences sharedPreferences) {
        Intrinsics.checkNotNullParameter(sharedPreferences, "sharedPreferences");
        this.a = sharedPreferences;
    }

    @Override // com.quizlet.data.token.a
    public final String a() {
        return this.a.getString("access_token", null);
    }

    @Override // com.quizlet.data.token.a
    public final void b(String str) {
        this.a.edit().putString("access_token", str).apply();
    }
}

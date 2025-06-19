package com.facebook;

import android.content.SharedPreferences;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.facebook.a, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1544a {
    public final SharedPreferences a;

    public C1544a(SharedPreferences sharedPreferences) {
        Intrinsics.checkNotNullParameter(sharedPreferences, "sharedPreferences");
        this.a = sharedPreferences;
    }

    public C1544a() {
        SharedPreferences sharedPreferences = o.a().getSharedPreferences("com.facebook.AccessTokenManager.SharedPreferences", 0);
        Intrinsics.checkNotNullExpressionValue(sharedPreferences, "getApplicationContext()\n…ME, Context.MODE_PRIVATE)");
        com.quizlet.shared.usecase.folderstudymaterials.b tokenCachingStrategyFactory = new com.quizlet.shared.usecase.folderstudymaterials.b(7);
        Intrinsics.checkNotNullParameter(sharedPreferences, "sharedPreferences");
        Intrinsics.checkNotNullParameter(tokenCachingStrategyFactory, "tokenCachingStrategyFactory");
        this.a = sharedPreferences;
    }
}

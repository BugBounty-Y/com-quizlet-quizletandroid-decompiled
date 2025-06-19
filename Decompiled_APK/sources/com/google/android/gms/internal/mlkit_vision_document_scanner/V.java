package com.google.android.gms.internal.mlkit_vision_document_scanner;

import android.content.SharedPreferences;

/* loaded from: classes2.dex */
public abstract class V {
    public static final /* synthetic */ int a = 0;

    public static void a(SharedPreferences sharedPreferences, String str, String str2) {
        sharedPreferences.edit().putString(str, str2).apply();
    }
}

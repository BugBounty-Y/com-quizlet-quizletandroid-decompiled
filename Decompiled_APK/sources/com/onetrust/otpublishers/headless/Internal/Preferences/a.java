package com.onetrust.otpublishers.headless.Internal.Preferences;

import android.content.Context;
import android.content.SharedPreferences;
import android.preference.PreferenceManager;
import androidx.annotation.NonNull;
import com.google.android.gms.internal.mlkit_vision_document_scanner.V;

/* loaded from: classes2.dex */
public final class a {
    public final SharedPreferences a;

    public a(@NonNull Context context) {
        this.a = PreferenceManager.getDefaultSharedPreferences(context);
    }

    public final void a(int i, String str) {
        this.a.edit().putInt(str, i).apply();
    }

    public final void b(String str) {
        SharedPreferences sharedPreferences = this.a;
        if (sharedPreferences.contains(str)) {
            sharedPreferences.edit().remove(str).apply();
        }
    }

    public final void c(String str, String str2) {
        V.a(this.a, str, str2);
    }

    public final int d(String str) {
        return this.a.getInt(str, -1);
    }

    public final String e(String str) {
        return this.a.getString(str, "");
    }
}

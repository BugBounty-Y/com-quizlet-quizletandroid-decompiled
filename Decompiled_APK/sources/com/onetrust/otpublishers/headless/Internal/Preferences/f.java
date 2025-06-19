package com.onetrust.otpublishers.headless.Internal.Preferences;

import android.content.Context;
import android.content.SharedPreferences;
import java.util.Map;
import java.util.Set;

/* loaded from: classes2.dex */
public final class f implements SharedPreferences {
    public final c a;
    public final SharedPreferences b;
    public final SharedPreferences c;

    public f(Context context, SharedPreferences sharedPreferences, String str) {
        this.b = sharedPreferences;
        SharedPreferences sharedPreferences2 = context.getSharedPreferences("com.onetrust.otpublishers.headless.preference.OTT_USER_" + new com.onetrust.otpublishers.headless.Internal.profile.c(context).n(str), 0);
        this.c = sharedPreferences2;
        this.a = new c(sharedPreferences, sharedPreferences2);
    }

    @Override // android.content.SharedPreferences
    public final boolean contains(String str) {
        return (com.onetrust.otpublishers.headless.Internal.Constants.a.a.contains(str) ? this.c : this.b).contains(str);
    }

    @Override // android.content.SharedPreferences
    public final SharedPreferences.Editor edit() {
        return this.a;
    }

    @Override // android.content.SharedPreferences
    public final Map getAll() {
        return null;
    }

    @Override // android.content.SharedPreferences
    public final boolean getBoolean(String str, boolean z) {
        return (com.onetrust.otpublishers.headless.Internal.Constants.a.a.contains(str) ? this.c : this.b).getBoolean(str, z);
    }

    @Override // android.content.SharedPreferences
    public final float getFloat(String str, float f) {
        return (com.onetrust.otpublishers.headless.Internal.Constants.a.a.contains(str) ? this.c : this.b).getFloat(str, f);
    }

    @Override // android.content.SharedPreferences
    public final int getInt(String str, int i) {
        return (com.onetrust.otpublishers.headless.Internal.Constants.a.a.contains(str) ? this.c : this.b).getInt(str, i);
    }

    @Override // android.content.SharedPreferences
    public final long getLong(String str, long j) {
        return (com.onetrust.otpublishers.headless.Internal.Constants.a.a.contains(str) ? this.c : this.b).getLong(str, j);
    }

    @Override // android.content.SharedPreferences
    public final String getString(String str, String str2) {
        return (com.onetrust.otpublishers.headless.Internal.Constants.a.a.contains(str) ? this.c : this.b).getString(str, str2);
    }

    @Override // android.content.SharedPreferences
    public final Set getStringSet(String str, Set set) {
        return (com.onetrust.otpublishers.headless.Internal.Constants.a.a.contains(str) ? this.c : this.b).getStringSet(str, set);
    }

    @Override // android.content.SharedPreferences
    public final void registerOnSharedPreferenceChangeListener(SharedPreferences.OnSharedPreferenceChangeListener onSharedPreferenceChangeListener) {
        this.b.registerOnSharedPreferenceChangeListener(onSharedPreferenceChangeListener);
        this.c.registerOnSharedPreferenceChangeListener(onSharedPreferenceChangeListener);
    }

    @Override // android.content.SharedPreferences
    public final void unregisterOnSharedPreferenceChangeListener(SharedPreferences.OnSharedPreferenceChangeListener onSharedPreferenceChangeListener) {
        this.b.unregisterOnSharedPreferenceChangeListener(onSharedPreferenceChangeListener);
        this.c.unregisterOnSharedPreferenceChangeListener(onSharedPreferenceChangeListener);
    }
}

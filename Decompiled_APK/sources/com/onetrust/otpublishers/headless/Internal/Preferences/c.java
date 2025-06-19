package com.onetrust.otpublishers.headless.Internal.Preferences;

import android.content.SharedPreferences;
import java.util.Set;

/* loaded from: classes2.dex */
public final class c implements SharedPreferences.Editor {
    public final SharedPreferences.Editor a;
    public final SharedPreferences.Editor b;

    public c(SharedPreferences sharedPreferences, SharedPreferences sharedPreferences2) {
        this.a = sharedPreferences.edit();
        this.b = sharedPreferences2.edit();
    }

    @Override // android.content.SharedPreferences.Editor
    public final void apply() {
        this.a.apply();
        this.b.apply();
    }

    @Override // android.content.SharedPreferences.Editor
    public final SharedPreferences.Editor clear() {
        this.a.clear();
        this.b.clear();
        return this;
    }

    @Override // android.content.SharedPreferences.Editor
    public final boolean commit() {
        return this.a.commit() && this.b.commit();
    }

    @Override // android.content.SharedPreferences.Editor
    public final SharedPreferences.Editor putBoolean(String str, boolean z) {
        (com.onetrust.otpublishers.headless.Internal.Constants.a.a.contains(str) ? this.b : this.a).putBoolean(str, z);
        return this;
    }

    @Override // android.content.SharedPreferences.Editor
    public final SharedPreferences.Editor putFloat(String str, float f) {
        (com.onetrust.otpublishers.headless.Internal.Constants.a.a.contains(str) ? this.b : this.a).putFloat(str, f);
        return this;
    }

    @Override // android.content.SharedPreferences.Editor
    public final SharedPreferences.Editor putInt(String str, int i) {
        (com.onetrust.otpublishers.headless.Internal.Constants.a.a.contains(str) ? this.b : this.a).putInt(str, i);
        return this;
    }

    @Override // android.content.SharedPreferences.Editor
    public final SharedPreferences.Editor putLong(String str, long j) {
        (com.onetrust.otpublishers.headless.Internal.Constants.a.a.contains(str) ? this.b : this.a).putLong(str, j);
        return this;
    }

    @Override // android.content.SharedPreferences.Editor
    public final SharedPreferences.Editor putString(String str, String str2) {
        (com.onetrust.otpublishers.headless.Internal.Constants.a.a.contains(str) ? this.b : this.a).putString(str, str2);
        return this;
    }

    @Override // android.content.SharedPreferences.Editor
    public final SharedPreferences.Editor putStringSet(String str, Set set) {
        (com.onetrust.otpublishers.headless.Internal.Constants.a.a.contains(str) ? this.b : this.a).putStringSet(str, set);
        return this;
    }

    @Override // android.content.SharedPreferences.Editor
    public final SharedPreferences.Editor remove(String str) {
        (com.onetrust.otpublishers.headless.Internal.Constants.a.a.contains(str) ? this.b : this.a).remove(str);
        return this;
    }
}

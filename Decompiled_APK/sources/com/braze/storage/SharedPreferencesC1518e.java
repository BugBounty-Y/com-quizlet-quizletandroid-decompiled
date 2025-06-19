package com.braze.storage;

import android.content.Context;
import android.content.SharedPreferences;
import com.braze.coroutine.BrazeCoroutineScope;
import java.util.Map;
import java.util.Set;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.InterfaceC5025j0;

/* renamed from: com.braze.storage.e, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class SharedPreferencesC1518e implements SharedPreferences {
    public final Context a;
    public SharedPreferences b;
    public final InterfaceC5025j0 c;

    public SharedPreferencesC1518e(Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter("persistent.com.appboy.storage.sdk_enabled_cache", "name");
        this.a = context;
        this.c = kotlinx.coroutines.E.A(BrazeCoroutineScope.INSTANCE, null, null, new C1516c(this, null), 3);
    }

    public final void a() throws Throwable {
        if (!this.c.d0()) {
            kotlinx.coroutines.E.D(kotlin.coroutines.n.a, new C1517d(this, null));
        }
        this.b = this.a.getSharedPreferences("persistent.com.appboy.storage.sdk_enabled_cache", 0);
    }

    @Override // android.content.SharedPreferences
    public final boolean contains(String str) throws Throwable {
        a();
        SharedPreferences sharedPreferences = this.b;
        if (sharedPreferences != null) {
            return sharedPreferences.contains(str);
        }
        Intrinsics.m("prefs");
        throw null;
    }

    @Override // android.content.SharedPreferences
    public final SharedPreferences.Editor edit() throws Throwable {
        a();
        SharedPreferences sharedPreferences = this.b;
        if (sharedPreferences == null) {
            Intrinsics.m("prefs");
            throw null;
        }
        SharedPreferences.Editor editorEdit = sharedPreferences.edit();
        Intrinsics.checkNotNullExpressionValue(editorEdit, "edit(...)");
        return editorEdit;
    }

    @Override // android.content.SharedPreferences
    public final Map getAll() throws Throwable {
        a();
        SharedPreferences sharedPreferences = this.b;
        if (sharedPreferences == null) {
            Intrinsics.m("prefs");
            throw null;
        }
        Map<String, ?> all = sharedPreferences.getAll();
        Intrinsics.checkNotNullExpressionValue(all, "getAll(...)");
        return all;
    }

    @Override // android.content.SharedPreferences
    public final boolean getBoolean(String str, boolean z) {
        a();
        SharedPreferences sharedPreferences = this.b;
        if (sharedPreferences != null) {
            return sharedPreferences.getBoolean(str, z);
        }
        Intrinsics.m("prefs");
        throw null;
    }

    @Override // android.content.SharedPreferences
    public final float getFloat(String str, float f) throws Throwable {
        a();
        SharedPreferences sharedPreferences = this.b;
        if (sharedPreferences != null) {
            return sharedPreferences.getFloat(str, f);
        }
        Intrinsics.m("prefs");
        throw null;
    }

    @Override // android.content.SharedPreferences
    public final int getInt(String str, int i) throws Throwable {
        a();
        SharedPreferences sharedPreferences = this.b;
        if (sharedPreferences != null) {
            return sharedPreferences.getInt(str, i);
        }
        Intrinsics.m("prefs");
        throw null;
    }

    @Override // android.content.SharedPreferences
    public final long getLong(String str, long j) throws Throwable {
        a();
        SharedPreferences sharedPreferences = this.b;
        if (sharedPreferences != null) {
            return sharedPreferences.getLong(str, j);
        }
        Intrinsics.m("prefs");
        throw null;
    }

    @Override // android.content.SharedPreferences
    public final String getString(String str, String str2) throws Throwable {
        a();
        SharedPreferences sharedPreferences = this.b;
        if (sharedPreferences != null) {
            return sharedPreferences.getString(str, str2);
        }
        Intrinsics.m("prefs");
        throw null;
    }

    @Override // android.content.SharedPreferences
    public final Set getStringSet(String str, Set set) throws Throwable {
        a();
        SharedPreferences sharedPreferences = this.b;
        if (sharedPreferences != null) {
            return sharedPreferences.getStringSet(str, set);
        }
        Intrinsics.m("prefs");
        throw null;
    }

    @Override // android.content.SharedPreferences
    public final void registerOnSharedPreferenceChangeListener(SharedPreferences.OnSharedPreferenceChangeListener onSharedPreferenceChangeListener) throws Throwable {
        a();
        SharedPreferences sharedPreferences = this.b;
        if (sharedPreferences != null) {
            sharedPreferences.registerOnSharedPreferenceChangeListener(onSharedPreferenceChangeListener);
        } else {
            Intrinsics.m("prefs");
            throw null;
        }
    }

    @Override // android.content.SharedPreferences
    public final void unregisterOnSharedPreferenceChangeListener(SharedPreferences.OnSharedPreferenceChangeListener onSharedPreferenceChangeListener) throws Throwable {
        a();
        SharedPreferences sharedPreferences = this.b;
        if (sharedPreferences != null) {
            sharedPreferences.unregisterOnSharedPreferenceChangeListener(onSharedPreferenceChangeListener);
        } else {
            Intrinsics.m("prefs");
            throw null;
        }
    }
}

package com.google.android.gms.internal.ads;

import android.content.Context;
import android.content.SharedPreferences;
import android.preference.PreferenceManager;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Objects;

/* renamed from: com.google.android.gms.internal.ads.Qc, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1757Qc {
    public final HashMap a = new HashMap();
    public final ArrayList b = new ArrayList();
    public final Context c;
    public final Fi d;

    public C1757Qc(Context context, Fi fi) {
        this.c = context;
        this.d = fi;
    }

    public final synchronized void a(String str) {
        try {
            HashMap map = this.a;
            if (map.containsKey(str)) {
                return;
            }
            SharedPreferences defaultSharedPreferences = Objects.equals(str, "__default__") ? PreferenceManager.getDefaultSharedPreferences(this.c) : this.c.getSharedPreferences(str, 0);
            SharedPreferencesOnSharedPreferenceChangeListenerC1751Pc sharedPreferencesOnSharedPreferenceChangeListenerC1751Pc = new SharedPreferencesOnSharedPreferenceChangeListenerC1751Pc(str, 0, this);
            map.put(str, sharedPreferencesOnSharedPreferenceChangeListenerC1751Pc);
            defaultSharedPreferences.registerOnSharedPreferenceChangeListener(sharedPreferencesOnSharedPreferenceChangeListenerC1751Pc);
        } catch (Throwable th) {
            throw th;
        }
    }
}

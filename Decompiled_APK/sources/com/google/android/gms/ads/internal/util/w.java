package com.google.android.gms.ads.internal.util;

import android.content.Context;
import android.content.SharedPreferences;
import android.preference.PreferenceManager;
import com.google.android.gms.internal.ads.AbstractC2773w7;
import com.google.android.gms.internal.ads.C2601s7;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Objects;

/* loaded from: classes2.dex */
public final class w {
    public final HashMap a = new HashMap();
    public final ArrayList b = new ArrayList();
    public final Context c;

    public w(Context context) {
        this.c = context;
    }

    public final void a() {
        C2601s7 c2601s7 = AbstractC2773w7.ta;
        com.google.android.gms.ads.internal.client.r rVar = com.google.android.gms.ads.internal.client.r.d;
        if (((Boolean) rVar.c.a(c2601s7)).booleanValue()) {
            F f = com.google.android.gms.ads.internal.j.C.c;
            HashMap mapJ = F.J((String) rVar.c.a(AbstractC2773w7.ya));
            for (String str : mapJ.keySet()) {
                synchronized (this) {
                    try {
                        HashMap map = this.a;
                        if (!map.containsKey(str)) {
                            SharedPreferences defaultSharedPreferences = Objects.equals(str, "__default__") ? PreferenceManager.getDefaultSharedPreferences(this.c) : this.c.getSharedPreferences(str, 0);
                            v vVar = new v(this, str);
                            map.put(str, vVar);
                            defaultSharedPreferences.registerOnSharedPreferenceChangeListener(vVar);
                        }
                    } catch (Throwable th) {
                        throw th;
                    }
                }
            }
            u uVar = new u(mapJ);
            synchronized (this) {
                this.b.add(uVar);
            }
        }
    }
}

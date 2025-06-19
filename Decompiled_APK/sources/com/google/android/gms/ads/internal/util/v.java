package com.google.android.gms.ads.internal.util;

import android.content.SharedPreferences;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Set;

/* loaded from: classes2.dex */
public final class v implements SharedPreferences.OnSharedPreferenceChangeListener {
    public final String a;
    public final /* synthetic */ w b;

    public v(w wVar, String str) {
        this.b = wVar;
        this.a = str;
    }

    @Override // android.content.SharedPreferences.OnSharedPreferenceChangeListener
    public final void onSharedPreferenceChanged(SharedPreferences sharedPreferences, String str) {
        w wVar = this.b;
        synchronized (wVar) {
            try {
                Iterator it2 = wVar.b.iterator();
                while (it2.hasNext()) {
                    u uVar = (u) it2.next();
                    String str2 = this.a;
                    HashMap map = uVar.a;
                    if (map.containsKey(str2) && ((Set) map.get(str2)).contains(str)) {
                        com.google.android.gms.ads.internal.j.C.h.d().d(false);
                    }
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }
}

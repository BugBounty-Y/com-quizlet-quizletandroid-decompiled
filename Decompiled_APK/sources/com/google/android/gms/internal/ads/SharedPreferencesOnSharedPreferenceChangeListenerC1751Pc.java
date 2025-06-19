package com.google.android.gms.internal.ads;

import android.content.SharedPreferences;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import org.json.JSONException;
import org.json.JSONObject;

/* renamed from: com.google.android.gms.internal.ads.Pc, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class SharedPreferencesOnSharedPreferenceChangeListenerC1751Pc implements SharedPreferences.OnSharedPreferenceChangeListener {
    public final /* synthetic */ int a;
    public final Object b;
    public Object c;

    public /* synthetic */ SharedPreferencesOnSharedPreferenceChangeListenerC1751Pc(String str, int i, Object obj) {
        this.a = i;
        this.c = obj;
        this.b = str;
    }

    @Override // android.content.SharedPreferences.OnSharedPreferenceChangeListener
    public final void onSharedPreferenceChanged(SharedPreferences sharedPreferences, String str) throws JSONException {
        switch (this.a) {
            case 0:
                C1757Qc c1757Qc = (C1757Qc) this.c;
                synchronized (c1757Qc) {
                    try {
                        Iterator it2 = c1757Qc.b.iterator();
                        while (it2.hasNext()) {
                            C1745Oc c1745Oc = (C1745Oc) it2.next();
                            String str2 = (String) this.b;
                            C1757Qc c1757Qc2 = c1745Oc.a;
                            HashMap map = c1745Oc.b;
                            if (map.containsKey(str2) && ((Set) map.get(str2)).contains(str)) {
                                Fi fi = c1757Qc2.d;
                                ((C1697Gc) fi.c).a(-1, ((com.google.android.gms.common.util.a) fi.b).currentTimeMillis());
                            }
                        }
                    } finally {
                    }
                }
                return;
            case 1:
                Kk kk = (Kk) this.c;
                kk.j.set(com.google.android.gms.internal.mlkit_vision_common.U2.d(kk.b, (String) this.b));
                return;
            default:
                if (str != null && ((List) this.c).contains(str)) {
                    try {
                        Object obj = sharedPreferences.getAll().get(str);
                        JSONObject jSONObject = (JSONObject) this.b;
                        if (obj == null) {
                            jSONObject.remove(str);
                        } else {
                            jSONObject.put(str, obj);
                        }
                        return;
                    } catch (JSONException e) {
                        com.google.android.gms.ads.internal.j.C.h.g("InspectorSharedPreferenceCollector.onSharedPreferenceChanged", e);
                        return;
                    }
                }
                return;
        }
    }

    public SharedPreferencesOnSharedPreferenceChangeListenerC1751Pc() {
        this.a = 2;
        this.b = new JSONObject();
    }
}

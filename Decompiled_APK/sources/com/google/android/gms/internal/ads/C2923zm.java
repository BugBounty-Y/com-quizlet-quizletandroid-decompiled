package com.google.android.gms.internal.ads;

import android.os.Bundle;
import com.google.android.gms.ads.internal.client.zze;
import com.google.android.gms.ads.internal.client.zzv;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import org.json.JSONException;
import org.json.JSONObject;

/* renamed from: com.google.android.gms.internal.ads.zm, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2923zm {
    public final String c;
    public Xp d = null;
    public Vp e = null;
    public zzv f = null;
    public final Map b = Collections.synchronizedMap(new HashMap());
    public final List a = Collections.synchronizedList(new ArrayList());

    public C2923zm(String str) {
        this.c = str;
    }

    public static String b(Vp vp) {
        return ((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.I3)).booleanValue() ? vp.p0 : vp.w;
    }

    public final void a(Vp vp) {
        String strB = b(vp);
        Map map = this.b;
        Object obj = map.get(strB);
        List list = this.a;
        int iIndexOf = list.indexOf(obj);
        if (iIndexOf < 0 || iIndexOf >= map.size()) {
            iIndexOf = list.indexOf(this.f);
        }
        if (iIndexOf < 0 || iIndexOf >= map.size()) {
            return;
        }
        this.f = (zzv) list.get(iIndexOf);
        while (true) {
            iIndexOf++;
            if (iIndexOf >= list.size()) {
                return;
            }
            zzv zzvVar = (zzv) list.get(iIndexOf);
            zzvVar.b = 0L;
            zzvVar.c = null;
        }
    }

    public final synchronized void c(Vp vp, int i) {
        Map map = this.b;
        String strB = b(vp);
        if (map.containsKey(strB)) {
            return;
        }
        Bundle bundle = new Bundle();
        JSONObject jSONObject = vp.v;
        Iterator<String> itKeys = jSONObject.keys();
        while (itKeys.hasNext()) {
            String next = itKeys.next();
            try {
                bundle.putString(next, jSONObject.getString(next));
            } catch (JSONException unused) {
            }
        }
        zzv zzvVar = new zzv(vp.E, 0L, null, bundle, vp.F, vp.G, vp.H, vp.I);
        try {
            this.a.add(i, zzvVar);
        } catch (IndexOutOfBoundsException e) {
            com.google.android.gms.ads.internal.j.C.h.h("AdapterResponseInfoCollector.addAdapterResponseInfoEntryAtLocation", e);
        }
        this.b.put(strB, zzvVar);
    }

    public final void d(Vp vp, long j, zze zzeVar, boolean z) {
        String strB = b(vp);
        Map map = this.b;
        if (map.containsKey(strB)) {
            if (this.e == null) {
                this.e = vp;
            }
            zzv zzvVar = (zzv) map.get(strB);
            zzvVar.b = j;
            zzvVar.c = zzeVar;
            if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.I6)).booleanValue() && z) {
                this.f = zzvVar;
            }
        }
    }
}

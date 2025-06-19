package com.google.android.gms.internal.ads;

import android.os.Handler;
import android.os.Looper;
import android.view.View;
import android.view.ViewGroup;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.WeakHashMap;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* renamed from: com.google.android.gms.internal.ads.hs, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2157hs {
    public static final C2157hs g = new C2157hs();
    public static final Handler h = new Handler(Looper.getMainLooper());
    public static Handler i = null;
    public static final C4 j = new C4(6);
    public static final C4 k = new C4(7);
    public long f;
    public final ArrayList a = new ArrayList();
    public final ArrayList b = new ArrayList();
    public final Tm d = new Tm();
    public final Fp c = new Fp(4);
    public final Fi e = new Fi(new C2326lq(27));

    public static void b() {
        if (i == null) {
            Handler handler = new Handler(Looper.getMainLooper());
            i = handler;
            handler.post(j);
            i.postDelayed(k, 200L);
        }
    }

    public final void a(View view, C2883yp c2883yp, JSONObject jSONObject, boolean z) {
        Object obj;
        boolean z2;
        int i2;
        if (AbstractC2025es.j(view) == null) {
            Tm tm = this.d;
            char c = ((HashSet) tm.e).contains(view) ? (char) 1 : tm.a ? (char) 2 : (char) 3;
            if (c == 3) {
                return;
            }
            JSONObject jSONObjectA = c2883yp.a(view);
            AbstractC1938cs.b(jSONObject, jSONObjectA);
            HashMap map = (HashMap) tm.b;
            if (map.size() == 0) {
                obj = null;
            } else {
                Object obj2 = (String) map.get(view);
                if (obj2 != null) {
                    map.remove(view);
                }
                obj = obj2;
            }
            boolean z3 = false;
            if (obj != null) {
                try {
                    jSONObjectA.put("adSessionId", obj);
                } catch (JSONException e) {
                    LA.l("Error with setting ad session id", e);
                }
                WeakHashMap weakHashMap = (WeakHashMap) tm.j;
                if (weakHashMap.containsKey(view)) {
                    weakHashMap.put(view, Boolean.TRUE);
                } else {
                    z3 = true;
                }
                try {
                    jSONObjectA.put("hasWindowFocus", Boolean.valueOf(z3));
                } catch (JSONException e2) {
                    LA.l("Error with setting has window focus", e2);
                }
                boolean zContains = ((HashSet) tm.i).contains(obj);
                Object objValueOf = Boolean.valueOf(zContains);
                if (zContains) {
                    try {
                        jSONObjectA.put("isPipActive", objValueOf);
                    } catch (JSONException e3) {
                        LA.l("Error with setting is picture-in-picture active", e3);
                    }
                }
                tm.a = true;
                return;
            }
            HashMap map2 = (HashMap) tm.c;
            C2069fs c2069fs = (C2069fs) map2.get(view);
            if (c2069fs != null) {
                map2.remove(view);
            }
            if (c2069fs != null) {
                Ur ur = c2069fs.a;
                JSONArray jSONArray = new JSONArray();
                ArrayList arrayList = c2069fs.b;
                int size = arrayList.size();
                for (int i3 = 0; i3 < size; i3++) {
                    jSONArray.put((String) arrayList.get(i3));
                }
                try {
                    jSONObjectA.put("isFriendlyObstructionFor", jSONArray);
                    jSONObjectA.put("friendlyObstructionClass", ur.b);
                    jSONObjectA.put("friendlyObstructionPurpose", ur.c);
                    jSONObjectA.put("friendlyObstructionReason", ur.d);
                } catch (JSONException e4) {
                    LA.l("Error with setting friendly obstruction", e4);
                }
                z2 = true;
            } else {
                z2 = false;
            }
            boolean z4 = z || z2;
            boolean z5 = c == 1;
            c2883yp.getClass();
            if (view instanceof ViewGroup) {
                ViewGroup viewGroup = (ViewGroup) view;
                if (!z5) {
                    for (int i4 = 0; i4 < viewGroup.getChildCount(); i4++) {
                        a(viewGroup.getChildAt(i4), c2883yp, jSONObjectA, z4);
                    }
                    return;
                }
                HashMap map3 = new HashMap();
                for (int i5 = 0; i5 < viewGroup.getChildCount(); i5++) {
                    View childAt = viewGroup.getChildAt(i5);
                    ArrayList arrayList2 = (ArrayList) map3.get(Float.valueOf(childAt.getZ()));
                    if (arrayList2 == null) {
                        arrayList2 = new ArrayList();
                        map3.put(Float.valueOf(childAt.getZ()), arrayList2);
                    }
                    arrayList2.add(childAt);
                }
                ArrayList arrayList3 = new ArrayList(map3.keySet());
                Collections.sort(arrayList3);
                int size2 = arrayList3.size();
                int i6 = 0;
                while (i6 < size2) {
                    ArrayList arrayList4 = (ArrayList) map3.get((Float) arrayList3.get(i6));
                    int size3 = arrayList4.size();
                    int i7 = 0;
                    while (true) {
                        i2 = i6 + 1;
                        if (i7 < size3) {
                            a((View) arrayList4.get(i7), c2883yp, jSONObjectA, z4);
                            i7++;
                        }
                    }
                    i6 = i2;
                }
            }
        }
    }
}

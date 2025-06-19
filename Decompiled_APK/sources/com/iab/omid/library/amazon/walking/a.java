package com.iab.omid.library.amazon.walking;

import android.os.Handler;
import android.os.Looper;
import android.util.Log;
import android.view.View;
import android.view.ViewGroup;
import androidx.emoji2.text.n;
import com.google.android.gms.internal.ads.Em;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3771z;
import com.google.firebase.crashlytics.internal.common.j;
import com.iab.omid.library.amazon.internal.e;
import com.quizlet.data.repository.qclass.c;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.WeakHashMap;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public final class a {
    public static final a g = new a();
    public static final Handler h = new Handler(Looper.getMainLooper());
    public static Handler i = null;
    public static final n j = new n(3);
    public static final n k = new n(4);
    public long f;
    public final ArrayList a = new ArrayList();
    public final ArrayList b = new ArrayList();
    public final Em d = new Em();
    public final com.quizlet.data.repository.explanations.myexplanations.a c = new com.quizlet.data.repository.explanations.myexplanations.a(13);
    public final c e = new c(new com.quizlet.data.repository.folderset.c(9), (byte) 0);

    public static void b() {
        if (i == null) {
            Handler handler = new Handler(Looper.getMainLooper());
            i = handler;
            handler.post(j);
            i.postDelayed(k, 200L);
        }
    }

    public final void a(View view, j jVar, JSONObject jSONObject, boolean z) {
        Object obj;
        boolean z2;
        if (AbstractC3771z.a(view) == null) {
            Em em = this.d;
            char c = ((HashSet) em.e).contains(view) ? (char) 1 : em.a ? (char) 2 : (char) 3;
            if (c == 3) {
                return;
            }
            JSONObject jSONObjectA = jVar.a(view);
            com.iab.omid.library.amazon.utils.b.c(jSONObject, jSONObjectA);
            HashMap map = (HashMap) em.b;
            if (map.size() == 0) {
                obj = null;
            } else {
                obj = (String) map.get(view);
                if (obj != null) {
                    map.remove(view);
                }
            }
            boolean z3 = false;
            if (obj != null) {
                try {
                    jSONObjectA.put("adSessionId", obj);
                } catch (JSONException e) {
                    Log.e("OMIDLIB", "Error with setting ad session id", e);
                }
                WeakHashMap weakHashMap = (WeakHashMap) em.i;
                if (weakHashMap.containsKey(view)) {
                    weakHashMap.put(view, Boolean.TRUE);
                } else {
                    z3 = true;
                }
                try {
                    jSONObjectA.put("hasWindowFocus", Boolean.valueOf(z3));
                } catch (JSONException e2) {
                    Log.e("OMIDLIB", "Error with setting has window focus", e2);
                }
                em.a = true;
                return;
            }
            HashMap map2 = (HashMap) em.c;
            b bVar = (b) map2.get(view);
            if (bVar != null) {
                map2.remove(view);
            }
            if (bVar != null) {
                e eVar = bVar.a;
                JSONArray jSONArray = new JSONArray();
                Iterator it2 = bVar.b.iterator();
                while (it2.hasNext()) {
                    jSONArray.put((String) it2.next());
                }
                try {
                    jSONObjectA.put("isFriendlyObstructionFor", jSONArray);
                    jSONObjectA.put("friendlyObstructionClass", eVar.b);
                    jSONObjectA.put("friendlyObstructionPurpose", eVar.c);
                    jSONObjectA.put("friendlyObstructionReason", (Object) null);
                } catch (JSONException e3) {
                    Log.e("OMIDLIB", "Error with setting friendly obstruction", e3);
                }
                z2 = true;
            } else {
                z2 = false;
            }
            boolean z4 = z || z2;
            boolean z5 = c == 1;
            jVar.getClass();
            if (view instanceof ViewGroup) {
                ViewGroup viewGroup = (ViewGroup) view;
                int i2 = 0;
                if (!z5) {
                    while (i2 < viewGroup.getChildCount()) {
                        a(viewGroup.getChildAt(i2), jVar, jSONObjectA, z4);
                        i2++;
                    }
                    return;
                }
                HashMap map3 = new HashMap();
                while (i2 < viewGroup.getChildCount()) {
                    View childAt = viewGroup.getChildAt(i2);
                    ArrayList arrayList = (ArrayList) map3.get(Float.valueOf(childAt.getZ()));
                    if (arrayList == null) {
                        arrayList = new ArrayList();
                        map3.put(Float.valueOf(childAt.getZ()), arrayList);
                    }
                    arrayList.add(childAt);
                    i2++;
                }
                ArrayList arrayList2 = new ArrayList(map3.keySet());
                Collections.sort(arrayList2);
                Iterator it3 = arrayList2.iterator();
                while (it3.hasNext()) {
                    Iterator it4 = ((ArrayList) map3.get((Float) it3.next())).iterator();
                    while (it4.hasNext()) {
                        a((View) it4.next(), jVar, jSONObjectA, z4);
                    }
                }
            }
        }
    }
}

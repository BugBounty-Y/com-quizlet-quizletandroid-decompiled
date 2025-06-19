package com.iab.omid.library.pubmatic.processor;

import android.view.View;
import androidx.annotation.NonNull;
import com.iab.omid.library.pubmatic.processor.a;
import com.iab.omid.library.pubmatic.utils.e;
import com.iab.omid.library.pubmatic.utils.h;
import java.util.ArrayList;
import java.util.Collection;
import java.util.IdentityHashMap;
import java.util.Iterator;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public class c implements a {
    private final a a;

    public c(a aVar) {
        this.a = aVar;
    }

    @NonNull
    public ArrayList<View> a() {
        View rootView;
        ArrayList<View> arrayList = new ArrayList<>();
        com.iab.omid.library.pubmatic.internal.c cVarC = com.iab.omid.library.pubmatic.internal.c.c();
        if (cVarC != null) {
            Collection<com.iab.omid.library.pubmatic.adsession.a> collectionA = cVarC.a();
            IdentityHashMap identityHashMap = new IdentityHashMap((collectionA.size() * 2) + 3);
            Iterator<com.iab.omid.library.pubmatic.adsession.a> it2 = collectionA.iterator();
            while (it2.hasNext()) {
                View viewC = it2.next().c();
                if (viewC != null && h.e(viewC) && (rootView = viewC.getRootView()) != null && !identityHashMap.containsKey(rootView)) {
                    identityHashMap.put(rootView, rootView);
                    float fC = h.c(rootView);
                    int size = arrayList.size();
                    while (size > 0 && h.c(arrayList.get(size - 1)) > fC) {
                        size--;
                    }
                    arrayList.add(size, rootView);
                }
            }
        }
        return arrayList;
    }

    @Override // com.iab.omid.library.pubmatic.processor.a
    public JSONObject a(View view) throws JSONException {
        JSONObject jSONObjectA = com.iab.omid.library.pubmatic.utils.c.a(0, 0, 0, 0);
        com.iab.omid.library.pubmatic.utils.c.a(jSONObjectA, e.a());
        return jSONObjectA;
    }

    @Override // com.iab.omid.library.pubmatic.processor.a
    public void a(View view, JSONObject jSONObject, a.InterfaceC0003a interfaceC0003a, boolean z, boolean z2) {
        Iterator<View> it2 = a().iterator();
        while (it2.hasNext()) {
            interfaceC0003a.a(it2.next(), this.a, jSONObject, z2);
        }
    }
}

package com.iab.omid.library.pubmatic.processor;

import android.annotation.TargetApi;
import android.view.View;
import android.view.ViewGroup;
import com.iab.omid.library.pubmatic.processor.a;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public class d implements a {
    private final int[] a = new int[2];

    @TargetApi(21)
    private void b(ViewGroup viewGroup, JSONObject jSONObject, a.InterfaceC0003a interfaceC0003a, boolean z) {
        HashMap map = new HashMap();
        for (int i = 0; i < viewGroup.getChildCount(); i++) {
            View childAt = viewGroup.getChildAt(i);
            ArrayList arrayList = (ArrayList) map.get(Float.valueOf(childAt.getZ()));
            if (arrayList == null) {
                arrayList = new ArrayList();
                map.put(Float.valueOf(childAt.getZ()), arrayList);
            }
            arrayList.add(childAt);
        }
        ArrayList arrayList2 = new ArrayList(map.keySet());
        Collections.sort(arrayList2);
        Iterator it2 = arrayList2.iterator();
        while (it2.hasNext()) {
            Iterator it3 = ((ArrayList) map.get((Float) it2.next())).iterator();
            while (it3.hasNext()) {
                interfaceC0003a.a((View) it3.next(), this, jSONObject, z);
            }
        }
    }

    @Override // com.iab.omid.library.pubmatic.processor.a
    public JSONObject a(View view) {
        if (view == null) {
            return com.iab.omid.library.pubmatic.utils.c.a(0, 0, 0, 0);
        }
        int width = view.getWidth();
        int height = view.getHeight();
        view.getLocationOnScreen(this.a);
        int[] iArr = this.a;
        return com.iab.omid.library.pubmatic.utils.c.a(iArr[0], iArr[1], width, height);
    }

    @Override // com.iab.omid.library.pubmatic.processor.a
    public void a(View view, JSONObject jSONObject, a.InterfaceC0003a interfaceC0003a, boolean z, boolean z2) {
        if (view instanceof ViewGroup) {
            ViewGroup viewGroup = (ViewGroup) view;
            if (z) {
                b(viewGroup, jSONObject, interfaceC0003a, z2);
            } else {
                a(viewGroup, jSONObject, interfaceC0003a, z2);
            }
        }
    }

    private void a(ViewGroup viewGroup, JSONObject jSONObject, a.InterfaceC0003a interfaceC0003a, boolean z) {
        for (int i = 0; i < viewGroup.getChildCount(); i++) {
            interfaceC0003a.a(viewGroup.getChildAt(i), this, jSONObject, z);
        }
    }
}

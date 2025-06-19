package com.braze.triggers.conditions.logical;

import com.braze.support.BrazeLogger;
import java.util.ArrayList;
import java.util.Iterator;
import org.json.JSONArray;

/* loaded from: classes.dex */
public abstract class b implements com.braze.triggers.conditions.c {
    public static final String b = BrazeLogger.getBrazeLogTag((Class<?>) b.class);
    public final ArrayList a;

    public b(ArrayList arrayList) {
        this.a = arrayList;
    }

    @Override // com.braze.models.IPutIntoJson
    public final JSONArray forJsonPut() {
        JSONArray jSONArray = new JSONArray();
        try {
            Iterator it2 = this.a.iterator();
            while (it2.hasNext()) {
                jSONArray.put(((com.braze.triggers.conditions.c) it2.next()).forJsonPut());
            }
        } catch (Exception e) {
            BrazeLogger.e(b, "Caught exception creating Json.", e);
        }
        return jSONArray;
    }
}

package com.braze.triggers.conditions;

import com.braze.support.BrazeLogger;
import java.util.ArrayList;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes.dex */
public abstract class l implements d {
    public static final String b = BrazeLogger.getBrazeLogTag((Class<?>) l.class);
    public final com.braze.triggers.conditions.logical.a a;

    public l(JSONObject jSONObject) throws JSONException {
        JSONArray jSONArray = jSONObject.getJSONObject("data").getJSONArray("property_filters");
        ArrayList arrayList = new ArrayList();
        for (int i = 0; i < jSONArray.length(); i++) {
            JSONArray jSONArray2 = jSONArray.getJSONArray(i);
            ArrayList arrayList2 = new ArrayList();
            for (int i2 = 0; i2 < jSONArray2.length(); i2++) {
                arrayList2.add(new g(jSONArray2.getJSONObject(i2)));
            }
            arrayList.add(new com.braze.triggers.conditions.logical.c(arrayList2));
        }
        this.a = new com.braze.triggers.conditions.logical.a(arrayList);
    }

    public JSONObject b() throws JSONException {
        JSONObject jSONObject = new JSONObject();
        try {
            JSONObject jSONObject2 = new JSONObject();
            jSONObject2.put("property_filters", this.a.forJsonPut());
            jSONObject.put("data", jSONObject2);
            return jSONObject;
        } catch (JSONException e) {
            BrazeLogger.e(b, "Caught exception creating Json.", e);
            return jSONObject;
        }
    }
}

package com.braze.triggers.conditions;

import com.braze.support.StringUtils;
import com.quizlet.db.data.models.persisted.fields.DBUserFields;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes.dex */
public final class a implements d {
    public final String a;

    public a(JSONObject jSONObject) {
        this.a = jSONObject.getJSONObject("data").getString("event_name");
    }

    @Override // com.braze.triggers.conditions.c
    public final boolean a(com.braze.triggers.events.b bVar) {
        if (!(bVar instanceof com.braze.triggers.events.a)) {
            return false;
        }
        com.braze.triggers.events.a aVar = (com.braze.triggers.events.a) bVar;
        return !StringUtils.isNullOrBlank(aVar.f) && aVar.f.equals(this.a);
    }

    @Override // com.braze.models.IPutIntoJson
    public final Object forJsonPut() throws JSONException {
        try {
            JSONObject jSONObject = new JSONObject();
            jSONObject.put(DBUserFields.Names.USER_UPGRADE_TYPE, "custom_event");
            JSONObject jSONObject2 = new JSONObject();
            jSONObject2.put("event_name", this.a);
            jSONObject.put("data", jSONObject2);
            return jSONObject;
        } catch (JSONException unused) {
            return null;
        }
    }
}

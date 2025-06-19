package com.braze.triggers.conditions;

import com.braze.support.StringUtils;
import com.quizlet.db.data.models.persisted.fields.DBUserFields;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes.dex */
public final class j implements d {
    public final String a;

    public j(JSONObject jSONObject) {
        JSONObject jSONObjectOptJSONObject = jSONObject.optJSONObject("data");
        if (jSONObjectOptJSONObject == null || jSONObjectOptJSONObject.isNull("campaign_id")) {
            return;
        }
        this.a = jSONObjectOptJSONObject.optString("campaign_id", null);
    }

    @Override // com.braze.triggers.conditions.c
    public final boolean a(com.braze.triggers.events.b bVar) {
        if (!(bVar instanceof com.braze.triggers.events.g)) {
            return false;
        }
        if (StringUtils.isNullOrBlank(this.a)) {
            return true;
        }
        com.braze.triggers.events.g gVar = (com.braze.triggers.events.g) bVar;
        return !StringUtils.isNullOrBlank(gVar.e) && gVar.e.equals(this.a);
    }

    @Override // com.braze.models.IPutIntoJson
    public final Object forJsonPut() throws JSONException {
        try {
            JSONObject jSONObject = new JSONObject();
            jSONObject.put(DBUserFields.Names.USER_UPGRADE_TYPE, "push_click");
            if (this.a != null) {
                JSONObject jSONObject2 = new JSONObject();
                jSONObject2.putOpt("campaign_id", this.a);
                jSONObject.putOpt("data", jSONObject2);
            }
            return jSONObject;
        } catch (JSONException unused) {
            return null;
        }
    }
}

package com.braze.triggers.conditions;

import com.braze.support.StringUtils;
import com.quizlet.db.data.models.persisted.fields.DBUserFields;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes.dex */
public final class h implements d {
    public final String a;

    public h(JSONObject jSONObject) {
        JSONObject jSONObjectOptJSONObject = jSONObject.optJSONObject("data");
        if (jSONObjectOptJSONObject == null || jSONObjectOptJSONObject.isNull("product_id")) {
            return;
        }
        this.a = jSONObjectOptJSONObject.optString("product_id", null);
    }

    @Override // com.braze.triggers.conditions.c
    public final boolean a(com.braze.triggers.events.b bVar) {
        if (!(bVar instanceof com.braze.triggers.events.f)) {
            return false;
        }
        if (StringUtils.isNullOrBlank(this.a)) {
            return true;
        }
        com.braze.triggers.events.f fVar = (com.braze.triggers.events.f) bVar;
        return !StringUtils.isNullOrBlank(fVar.f) && fVar.f.equals(this.a);
    }

    @Override // com.braze.models.IPutIntoJson
    public final Object forJsonPut() throws JSONException {
        try {
            JSONObject jSONObject = new JSONObject();
            jSONObject.put(DBUserFields.Names.USER_UPGRADE_TYPE, "purchase");
            if (this.a != null) {
                JSONObject jSONObject2 = new JSONObject();
                jSONObject2.putOpt("product_id", this.a);
                jSONObject.putOpt("data", jSONObject2);
            }
            return jSONObject;
        } catch (JSONException unused) {
            return null;
        }
    }
}

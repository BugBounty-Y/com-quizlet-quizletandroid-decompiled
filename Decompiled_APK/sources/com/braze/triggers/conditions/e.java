package com.braze.triggers.conditions;

import com.braze.support.StringUtils;
import com.onetrust.otpublishers.headless.Public.Keys.OTUXParamsKeys;
import com.quizlet.db.data.models.persisted.fields.DBUserFields;
import java.util.HashSet;
import java.util.Iterator;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes.dex */
public final class e implements d {
    public final String a;
    public final HashSet b = new HashSet();

    public e(JSONObject jSONObject) throws JSONException {
        JSONObject jSONObject2 = jSONObject.getJSONObject("data");
        this.a = jSONObject2.getString("id");
        JSONArray jSONArrayOptJSONArray = jSONObject2.optJSONArray(OTUXParamsKeys.OT_UX_BUTTONS);
        if (jSONArrayOptJSONArray != null) {
            for (int i = 0; i < jSONArrayOptJSONArray.length(); i++) {
                this.b.add(jSONArrayOptJSONArray.getString(i));
            }
        }
    }

    @Override // com.braze.triggers.conditions.c
    public final boolean a(com.braze.triggers.events.b bVar) {
        if (bVar instanceof com.braze.triggers.events.d) {
            com.braze.triggers.events.d dVar = (com.braze.triggers.events.d) bVar;
            if (!StringUtils.isNullOrBlank(dVar.e) && dVar.e.equals(this.a)) {
                return this.b.size() > 0 ? !StringUtils.isNullOrBlank(dVar.f) && this.b.contains(dVar.f) : StringUtils.isNullOrBlank(dVar.f);
            }
        }
        return false;
    }

    @Override // com.braze.models.IPutIntoJson
    public final Object forJsonPut() throws JSONException {
        try {
            JSONObject jSONObject = new JSONObject();
            jSONObject.put(DBUserFields.Names.USER_UPGRADE_TYPE, "iam_click");
            JSONObject jSONObject2 = new JSONObject();
            jSONObject2.put("id", this.a);
            if (this.b.size() > 0) {
                JSONArray jSONArray = new JSONArray();
                Iterator it2 = this.b.iterator();
                while (it2.hasNext()) {
                    jSONArray.put((String) it2.next());
                }
                jSONObject2.put(OTUXParamsKeys.OT_UX_BUTTONS, jSONArray);
            }
            jSONObject.put("data", jSONObject2);
            return jSONObject;
        } catch (JSONException unused) {
            return null;
        }
    }
}

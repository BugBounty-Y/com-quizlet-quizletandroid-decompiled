package com.braze.triggers.conditions;

import com.quizlet.db.data.models.persisted.fields.DBUserFields;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes.dex */
public final class k implements d {
    @Override // com.braze.triggers.conditions.c
    public final boolean a(com.braze.triggers.events.b bVar) {
        return bVar instanceof com.braze.triggers.events.h;
    }

    @Override // com.braze.models.IPutIntoJson
    public final Object forJsonPut() throws JSONException {
        try {
            JSONObject jSONObject = new JSONObject();
            jSONObject.put(DBUserFields.Names.USER_UPGRADE_TYPE, "test");
            return jSONObject;
        } catch (JSONException unused) {
            return null;
        }
    }
}

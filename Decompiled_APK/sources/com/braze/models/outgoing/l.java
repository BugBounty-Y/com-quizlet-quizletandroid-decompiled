package com.braze.models.outgoing;

import com.braze.models.IPutIntoJson;
import kotlin.jvm.internal.Intrinsics;
import org.json.JSONArray;
import org.json.JSONObject;

/* loaded from: classes.dex */
public final class l implements IPutIntoJson, com.braze.models.k {
    public final JSONObject a;
    public final JSONArray b;

    public l(JSONObject userObject) {
        Intrinsics.checkNotNullParameter(userObject, "userObject");
        this.a = userObject;
        this.b = new JSONArray().put(userObject);
    }

    @Override // com.braze.models.IPutIntoJson
    public final Object forJsonPut() {
        JSONArray jsonArrayForJsonPut = this.b;
        Intrinsics.checkNotNullExpressionValue(jsonArrayForJsonPut, "jsonArrayForJsonPut");
        return jsonArrayForJsonPut;
    }

    @Override // com.braze.models.k
    public final boolean isEmpty() {
        return this.a.length() == 0 || (this.a.length() == 1 && this.a.has("user_id"));
    }
}

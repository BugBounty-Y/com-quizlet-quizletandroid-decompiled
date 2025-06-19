package com.braze.models.push;

import com.braze.enums.e;
import kotlin.jvm.internal.Intrinsics;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes.dex */
public final class a extends com.braze.models.outgoing.event.b {
    /* JADX WARN: Illegal instructions before constructor call */
    public a(String campaignId, long j) throws JSONException {
        Intrinsics.checkNotNullParameter(campaignId, "campaignId");
        e eVar = e.K;
        JSONObject jSONObjectPut = new JSONObject().put("cid", campaignId);
        Intrinsics.checkNotNullExpressionValue(jSONObjectPut, "put(...)");
        super(eVar, jSONObjectPut, j, 8);
    }
}

package com.braze.models.response;

import kotlin.jvm.functions.Function1;
import org.json.JSONArray;
import org.json.JSONException;

/* loaded from: classes.dex */
public final class l implements Function1 {
    public final /* synthetic */ JSONArray a;

    public l(JSONArray jSONArray) {
        this.a = jSONArray;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) throws JSONException {
        Object obj2 = this.a.get(((Number) obj).intValue());
        if (obj2 != null) {
            return (String) obj2;
        }
        throw new NullPointerException("null cannot be cast to non-null type kotlin.String");
    }
}

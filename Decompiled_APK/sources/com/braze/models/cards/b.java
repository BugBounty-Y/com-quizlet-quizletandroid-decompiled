package com.braze.models.cards;

import kotlin.jvm.functions.Function1;
import org.json.JSONArray;

/* loaded from: classes.dex */
public final class b implements Function1 {
    public final /* synthetic */ JSONArray a;

    public b(JSONArray jSONArray) {
        this.a = jSONArray;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        return Boolean.valueOf(this.a.opt(((Number) obj).intValue()) instanceof String);
    }
}

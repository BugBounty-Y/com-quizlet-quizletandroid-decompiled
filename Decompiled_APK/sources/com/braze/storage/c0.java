package com.braze.storage;

import kotlin.jvm.functions.Function1;
import org.json.JSONArray;

/* loaded from: classes.dex */
public final class c0 implements Function1 {
    public final /* synthetic */ JSONArray a;

    public c0(JSONArray jSONArray) {
        this.a = jSONArray;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        return Boolean.valueOf(this.a.opt(((Number) obj).intValue()) instanceof String);
    }
}

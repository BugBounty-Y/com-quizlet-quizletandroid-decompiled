package com.braze.models;

import java.util.Objects;
import kotlin.jvm.functions.Function1;
import org.json.JSONArray;

/* loaded from: classes.dex */
public final class e implements Function1 {
    public final /* synthetic */ JSONArray a;

    public e(JSONArray jSONArray) {
        this.a = jSONArray;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        return Boolean.valueOf(Objects.nonNull(this.a.opt(((Number) obj).intValue())));
    }
}

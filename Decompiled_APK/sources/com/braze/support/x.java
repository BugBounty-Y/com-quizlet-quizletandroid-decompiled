package com.braze.support;

import kotlin.jvm.functions.Function0;
import org.json.JSONArray;

/* loaded from: classes.dex */
public final /* synthetic */ class x implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ JSONArray b;

    public /* synthetic */ x(int i, JSONArray jSONArray) {
        this.a = i;
        this.b = jSONArray;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return d.a(this.b);
            default:
                return com.braze.triggers.utils.c.b(this.b);
        }
    }
}

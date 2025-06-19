package com.braze;

import kotlin.jvm.functions.Function0;
import org.json.JSONObject;

/* loaded from: classes.dex */
public final /* synthetic */ class V implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ String b;
    public final /* synthetic */ JSONObject c;

    public /* synthetic */ V(int i, String str, JSONObject jSONObject) {
        this.a = i;
        this.b = str;
        this.c = jSONObject;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return BrazeUser.setCustomUserAttribute$lambda$49(this.b, this.c);
            default:
                return com.braze.models.outgoing.event.a.b(this.b, this.c);
        }
    }
}

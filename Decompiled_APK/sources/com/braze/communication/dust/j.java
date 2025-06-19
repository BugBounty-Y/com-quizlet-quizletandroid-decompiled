package com.braze.communication.dust;

import com.braze.enums.CardKey;
import com.braze.managers.n0;
import com.braze.models.response.m;
import com.braze.storage.p;
import com.braze.support.n;
import kotlin.jvm.functions.Function0;
import org.json.JSONObject;

/* loaded from: classes.dex */
public final /* synthetic */ class j implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ JSONObject b;

    public /* synthetic */ j(JSONObject jSONObject, int i) {
        this.a = i;
        this.b = jSONObject;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return h.a(this.b);
            case 1:
                return CardKey.Provider.getCardTypeFromJson$lambda$0(this.b);
            case 2:
                return n0.a(this.b);
            case 3:
                return com.braze.models.a.b(this.b);
            case 4:
                return com.braze.models.dust.c.b(this.b);
            case 5:
                return com.braze.models.response.g.a(this.b);
            case 6:
                return com.braze.models.response.g.b(this.b);
            case 7:
                return m.k(this.b);
            case 8:
                return p.b(this.b);
            case 9:
                return p.c(this.b);
            case 10:
                return p.d(this.b);
            case 11:
                return p.e(this.b);
            case 12:
                return com.braze.support.d.d(this.b);
            case 13:
                return com.braze.support.i.b(this.b);
            case 14:
                return com.braze.support.j.b(this.b);
            case 15:
                return com.braze.support.j.a(this.b);
            case 16:
                return n.a(this.b);
            case 17:
                return n.b(this.b);
            case 18:
                return n.c(this.b);
            case 19:
                return com.braze.triggers.actions.c.a(this.b);
            case 20:
                return com.braze.triggers.actions.f.a(this.b);
            case 21:
                return com.braze.triggers.utils.c.a(this.b);
            default:
                return com.braze.triggers.utils.c.b(this.b);
        }
    }
}

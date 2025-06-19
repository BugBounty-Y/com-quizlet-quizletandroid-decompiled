package com.android.billingclient.api;

import com.google.android.gms.internal.play_billing.AbstractC3819n0;
import com.google.android.gms.internal.play_billing.K;
import com.google.android.gms.internal.play_billing.W;

/* loaded from: classes.dex */
public final class e {
    public int a;
    public String b;

    public static d a() {
        d dVar = new d(1);
        dVar.c = "";
        return dVar;
    }

    public final String toString() {
        int i = this.a;
        int i2 = AbstractC3819n0.a;
        W w = K.c;
        Integer numValueOf = Integer.valueOf(i);
        return android.support.v4.media.session.a.m("Response Code: ", (!w.containsKey(numValueOf) ? K.RESPONSE_CODE_UNSPECIFIED : (K) w.get(numValueOf)).toString(), ", Debug Message: ", this.b);
    }
}

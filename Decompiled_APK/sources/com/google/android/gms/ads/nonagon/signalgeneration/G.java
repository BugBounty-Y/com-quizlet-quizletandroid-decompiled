package com.google.android.gms.ads.nonagon.signalgeneration;

import android.text.TextUtils;
import com.google.android.gms.internal.ads.Ek;
import com.google.android.gms.internal.ads.InterfaceC2618si;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public final class G implements InterfaceC2618si {
    public final Ek a;
    public final F b;
    public final String c;
    public final int d;

    public G(Ek ek, F f, String str, int i) {
        this.a = ek;
        this.b = f;
        this.c = str;
        this.d = i;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2618si
    public final void a(String str) {
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2618si
    public final void b(q qVar) {
        String strOptString;
        if (qVar == null || this.d == 2) {
            return;
        }
        boolean zIsEmpty = TextUtils.isEmpty(qVar.c);
        Ek ek = this.a;
        F f = this.b;
        if (zIsEmpty) {
            f.b(this.c, qVar.b, ek);
            return;
        }
        try {
            strOptString = new JSONObject(qVar.c).optString("request_id");
        } catch (JSONException e) {
            com.google.android.gms.ads.internal.j.C.h.h("RenderSignals.getRequestId", e);
            strOptString = null;
        }
        if (TextUtils.isEmpty(strOptString)) {
            return;
        }
        f.b(strOptString, qVar.c, ek);
    }
}

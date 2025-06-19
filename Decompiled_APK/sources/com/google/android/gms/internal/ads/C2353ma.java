package com.google.android.gms.internal.ads;

import java.util.List;
import org.json.JSONObject;

/* renamed from: com.google.android.gms.internal.ads.ma, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final /* synthetic */ class C2353ma implements InterfaceC2544qt {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;
    public final /* synthetic */ Object c;

    public /* synthetic */ C2353ma(int i, Object obj, Object obj2) {
        this.a = i;
        this.b = obj;
        this.c = obj2;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2544qt
    public final Object apply(Object obj) {
        switch (this.a) {
            case 0:
                InterfaceC2051fa interfaceC2051fa = (InterfaceC2051fa) obj;
                interfaceC2051fa.o((String) this.b, (InterfaceC2389n9) this.c);
                return interfaceC2051fa;
            default:
                List list = (List) obj;
                if (list == null || list.isEmpty()) {
                    return null;
                }
                JSONObject jSONObject = (JSONObject) this.c;
                String strOptString = jSONObject.optString("text");
                Integer numI = Gj.i("bg_color", jSONObject);
                Integer numI2 = Gj.i("text_color", jSONObject);
                int iOptInt = jSONObject.optInt("text_size", -1);
                jSONObject.optBoolean("allow_pub_rendering");
                int iOptInt2 = jSONObject.optInt("animation_ms", 1000);
                return new BinderC2388n8(strOptString, list, numI, numI2, iOptInt > 0 ? Integer.valueOf(iOptInt) : null, jSONObject.optInt("presentation_ms", 4000) + iOptInt2, ((zzbfv) ((Gj) this.b).h).e);
        }
    }
}

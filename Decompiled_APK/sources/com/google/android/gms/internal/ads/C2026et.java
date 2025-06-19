package com.google.android.gms.internal.ads;

import android.os.Bundle;
import java.util.function.Consumer;

/* renamed from: com.google.android.gms.internal.ads.et, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final /* synthetic */ class C2026et implements Consumer {
    public final /* synthetic */ int a;
    public final /* synthetic */ Bundle b;

    public /* synthetic */ C2026et(Bundle bundle, int i) {
        this.a = i;
        this.b = bundle;
    }

    @Override // java.util.function.Consumer
    public final void accept(Object obj) {
        Bundle bundle = this.b;
        String str = (String) obj;
        switch (this.a) {
            case 0:
                Gw gw = C2158ht.c;
                bundle.putString("sessionToken", str);
                break;
            case 1:
                Gw gw2 = C2158ht.c;
                bundle.putString("deeplinkUrl", str);
                break;
            case 2:
                Gw gw3 = C2158ht.c;
                bundle.putString("sessionToken", str);
                break;
            case 3:
                Gw gw4 = C2158ht.c;
                bundle.putString("appId", str);
                break;
            case 4:
                Gw gw5 = C2158ht.c;
                bundle.putString("thirdPartyAuthCallerId", str);
                break;
            case 5:
                Gw gw6 = C2158ht.c;
                bundle.putString("appId", str);
                break;
            case 6:
                Gw gw7 = C2158ht.c;
                bundle.putString("sessionToken", str);
                break;
            case 7:
                Gw gw8 = C2158ht.c;
                bundle.putString("appId", str);
                break;
            default:
                Gw gw9 = C2158ht.c;
                bundle.putString("adFieldEnifd", str);
                break;
        }
    }
}

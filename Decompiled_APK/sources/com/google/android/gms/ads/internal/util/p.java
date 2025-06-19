package com.google.android.gms.ads.internal.util;

import com.google.android.gms.internal.ads.A3;
import com.google.android.gms.internal.ads.B3;
import com.google.android.gms.internal.ads.C2313ld;
import com.google.android.gms.internal.ads.LA;
import java.io.IOException;
import java.util.Map;

/* loaded from: classes2.dex */
public final class p extends B3 {
    public final C2313ld m;
    public final com.google.android.gms.ads.internal.util.client.f n;

    public p(String str, C2313ld c2313ld) throws IOException {
        super(0, str, new com.google.android.gms.internal.instantapps.a(c2313ld, 23));
        this.m = c2313ld;
        com.google.android.gms.ads.internal.util.client.f fVar = new com.google.android.gms.ads.internal.util.client.f();
        this.n = fVar;
        if (com.google.android.gms.ads.internal.util.client.f.c()) {
            fVar.d("onNetworkRequest", new com.quizlet.data.repository.classmembership.c(str, "GET", (Object) null, (Object) null));
        }
    }

    @Override // com.google.android.gms.internal.ads.B3
    public final androidx.browser.customtabs.k a(A3 a3) {
        return new androidx.browser.customtabs.k(a3, LA.o(a3));
    }

    @Override // com.google.android.gms.internal.ads.B3
    public final void e(Object obj) throws IOException {
        byte[] bArr;
        A3 a3 = (A3) obj;
        Map map = a3.c;
        com.google.android.gms.ads.internal.util.client.f fVar = this.n;
        fVar.getClass();
        if (com.google.android.gms.ads.internal.util.client.f.c()) {
            int i = a3.a;
            fVar.d("onNetworkResponse", new com.android.billingclient.api.s(i, map, 12));
            if (i < 200 || i >= 300) {
                fVar.d("onNetworkRequestError", new com.google.android.gms.ads.internal.util.client.d(null));
            }
        }
        if (com.google.android.gms.ads.internal.util.client.f.c() && (bArr = a3.b) != null) {
            fVar.d("onNetworkResponseBody", new com.airbnb.lottie.network.c(bArr, 18));
        }
        this.m.c(a3);
    }
}

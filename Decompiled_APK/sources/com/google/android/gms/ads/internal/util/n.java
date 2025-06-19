package com.google.android.gms.ads.internal.util;

import com.google.android.gms.internal.ads.A3;
import com.google.android.gms.internal.ads.B3;
import com.google.android.gms.internal.ads.LA;
import com.j256.ormlite.stmt.query.SimpleComparison;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/* loaded from: classes2.dex */
public final class n extends B3 {
    public final Object m;
    public final o n;
    public final /* synthetic */ byte[] o;
    public final /* synthetic */ HashMap p;
    public final /* synthetic */ com.google.android.gms.ads.internal.util.client.f q;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public n(int i, String str, o oVar, com.quizlet.data.repository.widget.b bVar, byte[] bArr, HashMap map, com.google.android.gms.ads.internal.util.client.f fVar) {
        super(i, str, bVar);
        this.o = bArr;
        this.p = map;
        this.q = fVar;
        this.m = new Object();
        this.n = oVar;
    }

    @Override // com.google.android.gms.internal.ads.B3
    public final androidx.browser.customtabs.k a(A3 a3) {
        String str;
        String str2;
        byte[] bArr = a3.b;
        try {
            Map map = a3.c;
            String str3 = "ISO-8859-1";
            if (map != null && (str2 = (String) map.get("Content-Type")) != null) {
                String[] strArrSplit = str2.split(";", 0);
                int i = 1;
                while (true) {
                    if (i >= strArrSplit.length) {
                        break;
                    }
                    String[] strArrSplit2 = strArrSplit[i].trim().split(SimpleComparison.EQUAL_TO_OPERATION, 0);
                    if (strArrSplit2.length == 2 && strArrSplit2[0].equals("charset")) {
                        str3 = strArrSplit2[1];
                        break;
                    }
                    i++;
                }
            }
            str = new String(bArr, str3);
        } catch (UnsupportedEncodingException unused) {
            str = new String(bArr);
        }
        return new androidx.browser.customtabs.k(str, LA.o(a3));
    }

    @Override // com.google.android.gms.internal.ads.B3
    public final Map c() {
        HashMap map = this.p;
        return map == null ? Collections.EMPTY_MAP : map;
    }

    @Override // com.google.android.gms.internal.ads.B3
    public final void e(Object obj) throws IOException {
        o oVar;
        String str = (String) obj;
        com.google.android.gms.ads.internal.util.client.f fVar = this.q;
        if (com.google.android.gms.ads.internal.util.client.f.c() && str != null) {
            fVar.d("onNetworkResponseBody", new com.airbnb.lottie.network.c(str.getBytes(), 18));
        }
        synchronized (this.m) {
            oVar = this.n;
        }
        oVar.c(str);
    }

    @Override // com.google.android.gms.internal.ads.B3
    public final byte[] k() {
        byte[] bArr = this.o;
        if (bArr == null) {
            return null;
        }
        return bArr;
    }
}

package com.google.android.gms.internal.ads;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/* loaded from: classes2.dex */
public final class J3 {
    public long a;
    public final String b;
    public final String c;
    public final long d;
    public final long e;
    public final long f;
    public final long g;
    public final List h;

    /* JADX WARN: Illegal instructions before constructor call */
    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r0v0, types: [java.util.List] */
    /* JADX WARN: Type inference failed for: r0v1, types: [java.util.ArrayList] */
    /* JADX WARN: Type inference failed for: r0v2 */
    public J3(String str, C2683u3 c2683u3) {
        String str2 = c2683u3.b;
        long j = c2683u3.c;
        long j2 = c2683u3.d;
        long j3 = c2683u3.e;
        long j4 = c2683u3.f;
        List arrayList = c2683u3.h;
        if (arrayList == 0) {
            Map map = c2683u3.g;
            arrayList = new ArrayList(map.size());
            for (Map.Entry entry : map.entrySet()) {
                arrayList.add(new C2812x3((String) entry.getKey(), (String) entry.getValue()));
            }
        }
        this(str, str2, j, j2, j3, j4, arrayList);
    }

    public static J3 a(com.android.volley.toolbox.c cVar) throws IOException {
        if (com.android.volley.toolbox.d.s(cVar) != 538247942) {
            throw new IOException();
        }
        String strV = com.android.volley.toolbox.d.v(cVar);
        String strV2 = com.android.volley.toolbox.d.v(cVar);
        long jT = com.android.volley.toolbox.d.t(cVar);
        long jT2 = com.android.volley.toolbox.d.t(cVar);
        long jT3 = com.android.volley.toolbox.d.t(cVar);
        long jT4 = com.android.volley.toolbox.d.t(cVar);
        int iS = com.android.volley.toolbox.d.s(cVar);
        if (iS < 0) {
            throw new IOException(android.support.v4.media.session.a.f(iS, "readHeaderList size="));
        }
        List arrayList = iS == 0 ? Collections.EMPTY_LIST : new ArrayList();
        for (int i = 0; i < iS; i++) {
            arrayList.add(new C2812x3(com.android.volley.toolbox.d.v(cVar).intern(), com.android.volley.toolbox.d.v(cVar).intern()));
        }
        return new J3(strV, strV2, jT, jT2, jT3, jT4, arrayList);
    }

    public J3(String str, String str2, long j, long j2, long j3, long j4, List list) {
        this.b = str;
        this.c = true == "".equals(str2) ? null : str2;
        this.d = j;
        this.e = j2;
        this.f = j3;
        this.g = j4;
        this.h = list;
    }
}

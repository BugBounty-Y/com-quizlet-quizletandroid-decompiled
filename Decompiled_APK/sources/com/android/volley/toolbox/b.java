package com.android.volley.toolbox;

import com.android.volley.y;
import java.io.BufferedOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/* loaded from: classes.dex */
public final class b {
    public long a;
    public final String b;
    public final String c;
    public final long d;
    public final long e;
    public final long f;
    public final long g;
    public final List h;

    public b(String str, String str2, long j, long j2, long j3, long j4, List list) {
        this.b = str;
        this.c = "".equals(str2) ? null : str2;
        this.d = j;
        this.e = j2;
        this.f = j3;
        this.g = j4;
        this.h = list;
    }

    public static b a(c cVar) throws IOException {
        if (d.i(cVar) != 538247942) {
            throw new IOException();
        }
        String strK = d.k(cVar);
        String strK2 = d.k(cVar);
        long j = d.j(cVar);
        long j2 = d.j(cVar);
        long j3 = d.j(cVar);
        long j4 = d.j(cVar);
        int i = d.i(cVar);
        if (i < 0) {
            throw new IOException(android.support.v4.media.session.a.f(i, "readHeaderList size="));
        }
        List arrayList = i == 0 ? Collections.EMPTY_LIST : new ArrayList();
        for (int i2 = 0; i2 < i; i2++) {
            arrayList.add(new com.android.volley.e(d.k(cVar).intern(), d.k(cVar).intern()));
        }
        return new b(strK, strK2, j, j2, j3, j4, arrayList);
    }

    public final com.android.volley.a b(byte[] bArr) {
        com.android.volley.a aVar = new com.android.volley.a();
        aVar.a = bArr;
        aVar.b = this.c;
        aVar.c = this.d;
        aVar.d = this.e;
        aVar.e = this.f;
        aVar.f = this.g;
        TreeMap treeMap = new TreeMap(String.CASE_INSENSITIVE_ORDER);
        List<com.android.volley.e> list = this.h;
        for (com.android.volley.e eVar : list) {
            treeMap.put(eVar.a, eVar.b);
        }
        aVar.g = treeMap;
        aVar.h = Collections.unmodifiableList(list);
        return aVar;
    }

    public final boolean c(BufferedOutputStream bufferedOutputStream) throws IOException {
        try {
            d.m(bufferedOutputStream, 538247942);
            d.o(bufferedOutputStream, this.b);
            String str = this.c;
            if (str == null) {
                str = "";
            }
            d.o(bufferedOutputStream, str);
            d.n(bufferedOutputStream, this.d);
            d.n(bufferedOutputStream, this.e);
            d.n(bufferedOutputStream, this.f);
            d.n(bufferedOutputStream, this.g);
            List<com.android.volley.e> list = this.h;
            if (list != null) {
                d.m(bufferedOutputStream, list.size());
                for (com.android.volley.e eVar : list) {
                    d.o(bufferedOutputStream, eVar.a);
                    d.o(bufferedOutputStream, eVar.b);
                }
            } else {
                d.m(bufferedOutputStream, 0);
            }
            bufferedOutputStream.flush();
            return true;
        } catch (IOException e) {
            y.a("%s", e.toString());
            return false;
        }
    }

    /* JADX WARN: Illegal instructions before constructor call */
    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r0v0, types: [java.util.List] */
    /* JADX WARN: Type inference failed for: r0v1, types: [java.util.ArrayList] */
    /* JADX WARN: Type inference failed for: r0v2 */
    public b(String str, com.android.volley.a aVar) {
        String str2 = aVar.b;
        long j = aVar.c;
        long j2 = aVar.d;
        long j3 = aVar.e;
        long j4 = aVar.f;
        List arrayList = aVar.h;
        if (arrayList == 0) {
            Map map = aVar.g;
            arrayList = new ArrayList(map.size());
            for (Map.Entry entry : map.entrySet()) {
                arrayList.add(new com.android.volley.e((String) entry.getKey(), (String) entry.getValue()));
            }
        }
        this(str, str2, j, j2, j3, j4, arrayList);
    }
}

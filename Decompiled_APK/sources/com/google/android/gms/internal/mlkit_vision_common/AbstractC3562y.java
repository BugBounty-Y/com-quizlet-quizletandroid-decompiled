package com.google.android.gms.internal.mlkit_vision_common;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;

/* renamed from: com.google.android.gms.internal.mlkit_vision_common.y, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3562y {
    public static final /* synthetic */ int a = 0;

    public static com.android.volley.h a(com.android.volley.l lVar, long j, List list) {
        com.android.volley.a cacheEntry = lVar.getCacheEntry();
        if (cacheEntry == null) {
            return new com.android.volley.h(304, null, true, j, list);
        }
        TreeSet treeSet = new TreeSet(String.CASE_INSENSITIVE_ORDER);
        if (!list.isEmpty()) {
            Iterator it2 = list.iterator();
            while (it2.hasNext()) {
                treeSet.add(((com.android.volley.e) it2.next()).a);
            }
        }
        ArrayList arrayList = new ArrayList(list);
        List list2 = cacheEntry.h;
        if (list2 != null) {
            if (!list2.isEmpty()) {
                for (com.android.volley.e eVar : cacheEntry.h) {
                    if (!treeSet.contains(eVar.a)) {
                        arrayList.add(eVar);
                    }
                }
            }
        } else if (!cacheEntry.g.isEmpty()) {
            for (Map.Entry entry : cacheEntry.g.entrySet()) {
                if (!treeSet.contains(entry.getKey())) {
                    arrayList.add(new com.android.volley.e((String) entry.getKey(), (String) entry.getValue()));
                }
            }
        }
        return new com.android.volley.h(304, cacheEntry.a, true, j, arrayList);
    }

    public static byte[] b(InputStream inputStream, int i, com.android.volley.toolbox.a aVar) throws Throwable {
        byte[] bArrA;
        com.android.volley.toolbox.i iVar = new com.android.volley.toolbox.i(aVar, i);
        try {
            bArrA = aVar.a(1024);
            while (true) {
                try {
                    int i2 = inputStream.read(bArrA);
                    if (i2 == -1) {
                        break;
                    }
                    iVar.write(bArrA, 0, i2);
                } catch (Throwable th) {
                    th = th;
                    try {
                        inputStream.close();
                    } catch (IOException unused) {
                        com.android.volley.y.c("Error occurred when closing InputStream", new Object[0]);
                    }
                    aVar.b(bArrA);
                    iVar.close();
                    throw th;
                }
            }
            byte[] byteArray = iVar.toByteArray();
            try {
                inputStream.close();
            } catch (IOException unused2) {
                com.android.volley.y.c("Error occurred when closing InputStream", new Object[0]);
            }
            aVar.b(bArrA);
            iVar.close();
            return byteArray;
        } catch (Throwable th2) {
            th = th2;
            bArrA = null;
        }
    }
}

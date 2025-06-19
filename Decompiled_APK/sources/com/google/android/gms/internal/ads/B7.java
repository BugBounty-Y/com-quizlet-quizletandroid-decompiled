package com.google.android.gms.internal.ads;

import android.os.SystemClock;
import android.text.TextUtils;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.Map;

/* loaded from: classes2.dex */
public final class B7 {
    public final LinkedList a = new LinkedList();
    public final LinkedHashMap b;
    public final Object c;

    public B7(String str) {
        LinkedHashMap linkedHashMap = new LinkedHashMap();
        this.b = linkedHashMap;
        this.c = new Object();
        linkedHashMap.put("action", "make_wv");
        linkedHashMap.put("ad_format", str);
    }

    public static final C2902z7 d() {
        com.google.android.gms.ads.internal.j.C.k.getClass();
        return new C2902z7(SystemClock.elapsedRealtime(), null, null);
    }

    public final A7 a() {
        A7 a7;
        boolean zBooleanValue = ((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.T1)).booleanValue();
        StringBuilder sb = new StringBuilder();
        HashMap map = new HashMap();
        synchronized (this.c) {
            try {
                LinkedList<C2902z7> linkedList = this.a;
                for (C2902z7 c2902z7 : linkedList) {
                    long j = c2902z7.a;
                    String str = c2902z7.b;
                    C2902z7 c2902z72 = c2902z7.c;
                    if (c2902z72 != null && j > 0) {
                        long j2 = j - c2902z72.a;
                        sb.append(str);
                        sb.append('.');
                        sb.append(j2);
                        sb.append(',');
                        if (zBooleanValue) {
                            if (map.containsKey(Long.valueOf(c2902z72.a))) {
                                StringBuilder sb2 = (StringBuilder) map.get(Long.valueOf(c2902z72.a));
                                sb2.append('+');
                                sb2.append(str);
                            } else {
                                map.put(Long.valueOf(c2902z72.a), new StringBuilder(str));
                            }
                        }
                    }
                }
                linkedList.clear();
                String string = null;
                if (!TextUtils.isEmpty(null)) {
                    sb.append((String) null);
                } else if (sb.length() > 0) {
                    sb.setLength(sb.length() - 1);
                }
                StringBuilder sb3 = new StringBuilder();
                if (zBooleanValue) {
                    for (Map.Entry entry : map.entrySet()) {
                        sb3.append((CharSequence) entry.getValue());
                        sb3.append('.');
                        long jLongValue = ((Long) entry.getKey()).longValue();
                        com.google.android.gms.ads.internal.j jVar = com.google.android.gms.ads.internal.j.C;
                        jVar.k.getClass();
                        long jCurrentTimeMillis = System.currentTimeMillis();
                        jVar.k.getClass();
                        sb3.append(jCurrentTimeMillis + (jLongValue - SystemClock.elapsedRealtime()));
                        sb3.append(',');
                    }
                    if (sb3.length() > 0) {
                        sb3.setLength(sb3.length() - 1);
                    }
                    string = sb3.toString();
                }
                a7 = new A7(sb.toString(), string);
            } catch (Throwable th) {
                throw th;
            }
        }
        return a7;
    }

    public final void b(String str, String str2) {
        com.google.android.datatransport.cct.internal.s sVarC;
        if (TextUtils.isEmpty(str2) || (sVarC = com.google.android.gms.ads.internal.j.C.h.c()) == null) {
            return;
        }
        synchronized (this.c) {
            C2859y7 c2859y7 = (C2859y7) ((HashMap) sVarC.d).get(str);
            if (c2859y7 == null) {
                c2859y7 = C2859y7.b;
            }
            LinkedHashMap linkedHashMap = this.b;
            linkedHashMap.put(str, c2859y7.a((String) linkedHashMap.get(str), str2));
        }
    }

    public final void c(C2902z7 c2902z7, long j, String... strArr) {
        synchronized (this.c) {
            this.a.add(new C2902z7(j, strArr[0], c2902z7));
        }
    }
}

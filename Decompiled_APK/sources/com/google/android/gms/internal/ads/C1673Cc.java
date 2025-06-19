package com.google.android.gms.internal.ads;

import android.content.Context;
import com.google.android.gms.ads.internal.util.client.VersionInfoParcel;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/* renamed from: com.google.android.gms.internal.ads.Cc, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1673Cc implements InterfaceC1679Dc {
    public static final List l = Collections.synchronizedList(new ArrayList());
    public final KB a;
    public final LinkedHashMap b;
    public final Context e;
    public boolean f;
    public final zzbxs g;
    public final ArrayList c = new ArrayList();
    public final ArrayList d = new ArrayList();
    public final Object h = new Object();
    public final HashSet i = new HashSet();
    public boolean j = false;
    public boolean k = false;

    public C1673Cc(Context context, VersionInfoParcel versionInfoParcel, zzbxs zzbxsVar, String str) {
        com.google.android.gms.common.internal.u.i(zzbxsVar, "SafeBrowsing config is not present.");
        this.e = context.getApplicationContext() != null ? context.getApplicationContext() : context;
        this.b = new LinkedHashMap();
        this.g = zzbxsVar;
        Iterator it2 = zzbxsVar.e.iterator();
        while (it2.hasNext()) {
            this.i.add(((String) it2.next()).toLowerCase(Locale.ENGLISH));
        }
        this.i.remove("cookie".toLowerCase(Locale.ENGLISH));
        KB kbW = C2392nC.w();
        kbW.e();
        C2392nC.K((C2392nC) kbW.b, 9);
        if (str != null) {
            kbW.e();
            C2392nC.J((C2392nC) kbW.b, str);
            kbW.e();
            C2392nC.H((C2392nC) kbW.b, str);
        }
        LB lbW = MB.w();
        String str2 = this.g.a;
        if (str2 != null) {
            lbW.e();
            MB.x((MB) lbW.b, str2);
        }
        MB mb = (MB) lbW.c();
        kbW.e();
        C2392nC.G((C2392nC) kbW.b, mb);
        C2220jC c2220jCW = C2263kC.w();
        boolean zD = com.google.android.gms.common.wrappers.c.a(this.e).d();
        c2220jCW.e();
        C2263kC.z((C2263kC) c2220jCW.b, zD);
        String str3 = versionInfoParcel.a;
        if (str3 != null) {
            c2220jCW.e();
            C2263kC.x((C2263kC) c2220jCW.b, str3);
        }
        com.google.android.gms.common.c cVar = com.google.android.gms.common.c.b;
        Context context2 = this.e;
        cVar.getClass();
        long jA = com.google.android.gms.common.c.a(context2);
        if (jA > 0) {
            c2220jCW.e();
            C2263kC.y((C2263kC) c2220jCW.b, jA);
        }
        C2263kC c2263kC = (C2263kC) c2220jCW.c();
        kbW.e();
        C2392nC.F((C2392nC) kbW.b, c2263kC);
        this.a = kbW;
    }

    public final void a(String str, Map map, int i) {
        synchronized (this.h) {
            if (i == 3) {
                try {
                    this.k = true;
                } catch (Throwable th) {
                    throw th;
                }
            }
            LinkedHashMap linkedHashMap = this.b;
            if (linkedHashMap.containsKey(str)) {
                if (i == 3) {
                    C2134hC c2134hC = (C2134hC) linkedHashMap.get(str);
                    c2134hC.e();
                    C2178iC.D((C2178iC) c2134hC.b, 4);
                }
                return;
            }
            C2134hC c2134hCX = C2178iC.x();
            int i2 = i != 0 ? i != 1 ? i != 2 ? i != 3 ? 0 : 4 : 3 : 2 : 1;
            if (i2 != 0) {
                c2134hCX.e();
                C2178iC.D((C2178iC) c2134hCX.b, i2);
            }
            int size = linkedHashMap.size();
            c2134hCX.e();
            C2178iC.A((C2178iC) c2134hCX.b, size);
            c2134hCX.e();
            C2178iC.C((C2178iC) c2134hCX.b, str);
            SB sbW = UB.w();
            if (!this.i.isEmpty() && map != null) {
                for (Map.Entry entry : map.entrySet()) {
                    String str2 = entry.getKey() != null ? (String) entry.getKey() : "";
                    String str3 = entry.getValue() != null ? (String) entry.getValue() : "";
                    if (this.i.contains(str2.toLowerCase(Locale.ENGLISH))) {
                        QB qbW = RB.w();
                        Charset charset = WA.a;
                        C2905zA c2905zA = new C2905zA(str2.getBytes(charset));
                        qbW.e();
                        RB.x((RB) qbW.b, c2905zA);
                        C2905zA c2905zA2 = new C2905zA(str3.getBytes(charset));
                        qbW.e();
                        RB.y((RB) qbW.b, c2905zA2);
                        RB rb = (RB) qbW.c();
                        sbW.e();
                        UB.x((UB) sbW.b, rb);
                    }
                }
            }
            UB ub = (UB) sbW.c();
            c2134hCX.e();
            C2178iC.B((C2178iC) c2134hCX.b, ub);
            linkedHashMap.put(str, c2134hCX);
        }
    }

    public final void b(String str) {
        synchronized (this.h) {
            try {
                if (str == null) {
                    KB kb = this.a;
                    kb.e();
                    C2392nC.D((C2392nC) kb.b);
                } else {
                    KB kb2 = this.a;
                    kb2.e();
                    C2392nC.E((C2392nC) kb2.b, str);
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }
}

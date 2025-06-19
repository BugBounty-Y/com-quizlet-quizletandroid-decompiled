package com.google.android.gms.internal.ads;

import android.content.Context;
import android.net.Uri;
import android.text.TextUtils;
import com.google.android.gms.ads.internal.util.client.VersionInfoParcel;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;

/* renamed from: com.google.android.gms.internal.ads.qr, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2542qr {
    public final C2195in a;
    public final String b;
    public final String c;
    public final String d;
    public final Context e;
    public final C1893bq f;
    public final C1936cq g;
    public final com.google.android.gms.common.util.a h;
    public final P4 i;

    public C2542qr(C2195in c2195in, VersionInfoParcel versionInfoParcel, String str, String str2, Context context, C1893bq c1893bq, C1936cq c1936cq, com.google.android.gms.common.util.a aVar, P4 p4) {
        this.a = c2195in;
        this.b = versionInfoParcel.a;
        this.c = str;
        this.d = str2;
        this.e = context;
        this.f = c1893bq;
        this.g = c1936cq;
        this.h = aVar;
        this.i = p4;
    }

    public static String a(String str, String str2, String str3) {
        if (true == TextUtils.isEmpty(str3)) {
            str3 = "";
        }
        return str.replaceAll(str2, str3);
    }

    public final ArrayList b(C1849aq c1849aq, Vp vp, List list) {
        return c(c1849aq, vp, false, "", "", list);
    }

    public final ArrayList c(C1849aq c1849aq, Vp vp, boolean z, String str, String str2, List list) {
        long j;
        ArrayList arrayList = new ArrayList();
        Iterator it2 = list.iterator();
        while (it2.hasNext()) {
            boolean z2 = true;
            String strA = a(a(a((String) it2.next(), "@gw_adlocid@", ((C2023eq) c1849aq.a.b).f), "@gw_adnetrefresh@", true != z ? "0" : "1"), "@gw_sdkver@", this.b);
            if (vp != null) {
                String strA2 = a(a(a(strA, "@gw_qdata@", vp.y), "@gw_adnetid@", vp.x), "@gw_allocid@", vp.w);
                HashMap map = vp.w0;
                boolean z3 = vp.W;
                Context context = this.e;
                strA = AbstractC1795We.u(strA2, context, z3, map);
                if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.md)).booleanValue() && vp.e == 4) {
                    com.google.android.gms.ads.internal.util.F f = com.google.android.gms.ads.internal.j.C.c;
                    strA = a(strA, "@gw_aps@", true != com.google.android.gms.ads.internal.util.F.f(context) ? "0" : "1");
                }
            }
            C2195in c2195in = this.a;
            String strA3 = a(strA, "@gw_adnetstatus@", c2195in.b());
            synchronized (c2195in) {
                j = c2195in.h;
            }
            String strA4 = a(a(a(strA3, "@gw_ttr@", Long.toString(j, 10)), "@gw_seqnum@", this.c), "@gw_sessid@", this.d);
            boolean z4 = false;
            if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.F3)).booleanValue() && !TextUtils.isEmpty(str)) {
                z4 = true;
            }
            boolean zIsEmpty = TextUtils.isEmpty(str2);
            boolean z5 = !zIsEmpty;
            if (z4) {
                z2 = z5;
            } else {
                if (!zIsEmpty) {
                }
                arrayList.add(strA4);
            }
            if (this.i.c(Uri.parse(strA4))) {
                Uri.Builder builderBuildUpon = Uri.parse(strA4).buildUpon();
                if (z4) {
                    builderBuildUpon = builderBuildUpon.appendQueryParameter("ms", str);
                }
                if (z2) {
                    builderBuildUpon = builderBuildUpon.appendQueryParameter("attok", str2);
                }
                strA4 = builderBuildUpon.build().toString();
            }
            arrayList.add(strA4);
        }
        return arrayList;
    }
}

package com.google.android.gms.internal.ads;

import android.text.TextUtils;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/* renamed from: com.google.android.gms.internal.ads.in, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2195in {
    public final com.google.android.gms.common.util.a a;
    public final C2326lq b;
    public final C2584rr c;
    public final LinkedHashMap d = new LinkedHashMap();
    public final boolean e = ((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.L6)).booleanValue();
    public final C2923zm f;
    public boolean g;
    public long h;
    public long i;

    public C2195in(com.google.android.gms.common.util.a aVar, C2326lq c2326lq, C2923zm c2923zm, C2584rr c2584rr) {
        this.a = aVar;
        this.b = c2326lq;
        this.f = c2923zm;
        this.c = c2584rr;
    }

    public final synchronized void a(C1849aq c1849aq, Vp vp, com.google.common.util.concurrent.e eVar, C2542qr c2542qr) {
        Xp xp = (Xp) c1849aq.b.b;
        long jElapsedRealtime = this.a.elapsedRealtime();
        String str = vp.w;
        if (str != null) {
            this.d.put(vp, new C2152hn(str, vp.f0, 9, 0L, null));
            C2108gn c2108gn = new C2108gn(this, jElapsedRealtime, xp, vp, str, c2542qr, c1849aq);
            eVar.a(new Qv(0, eVar, c2108gn), AbstractC2270kd.g);
        }
    }

    public final synchronized String b() {
        ArrayList arrayList;
        try {
            arrayList = new ArrayList();
            Iterator it2 = this.d.entrySet().iterator();
            while (it2.hasNext()) {
                C2152hn c2152hn = (C2152hn) ((Map.Entry) it2.next()).getValue();
                if (c2152hn.c != Integer.MAX_VALUE) {
                    arrayList.add(c2152hn.toString());
                }
            }
        } catch (Throwable th) {
            throw th;
        }
        return TextUtils.join("_", arrayList);
    }

    public final synchronized void c(List list) {
        this.i = this.a.elapsedRealtime();
        Iterator it2 = list.iterator();
        while (it2.hasNext()) {
            Vp vp = (Vp) it2.next();
            String str = vp.w;
            if (!TextUtils.isEmpty(str)) {
                this.d.put(vp, new C2152hn(str, vp.f0, SubsamplingScaleImageView.TILE_SIZE_AUTO, 0L, null));
            }
        }
    }

    public final synchronized void d(Vp vp) {
        C2152hn c2152hn = (C2152hn) this.d.get(vp);
        if (c2152hn == null || this.g) {
            return;
        }
        c2152hn.c = 8;
    }
}

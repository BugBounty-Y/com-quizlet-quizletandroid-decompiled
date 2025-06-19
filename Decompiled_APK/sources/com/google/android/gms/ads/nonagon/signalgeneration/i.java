package com.google.android.gms.ads.nonagon.signalgeneration;

import android.content.Context;
import android.graphics.Point;
import android.net.Uri;
import android.os.Bundle;
import android.os.Parcel;
import android.os.RemoteException;
import android.text.TextUtils;
import com.google.android.gms.ads.internal.client.zzm;
import com.google.android.gms.ads.internal.util.client.VersionInfoParcel;
import com.google.android.gms.internal.ads.AbstractBinderC1781Uc;
import com.google.android.gms.internal.ads.AbstractC1911c8;
import com.google.android.gms.internal.ads.AbstractC2025es;
import com.google.android.gms.internal.ads.AbstractC2270kd;
import com.google.android.gms.internal.ads.AbstractC2330lu;
import com.google.android.gms.internal.ads.AbstractC2543qs;
import com.google.android.gms.internal.ads.AbstractC2773w7;
import com.google.android.gms.internal.ads.C1708Ib;
import com.google.android.gms.internal.ads.C1765Re;
import com.google.android.gms.internal.ads.C1843ak;
import com.google.android.gms.internal.ads.C1925cf;
import com.google.android.gms.internal.ads.C2067fq;
import com.google.android.gms.internal.ads.C2227jd;
import com.google.android.gms.internal.ads.C2412nq;
import com.google.android.gms.internal.ads.C2584rr;
import com.google.android.gms.internal.ads.C2601s7;
import com.google.android.gms.internal.ads.C2846xv;
import com.google.android.gms.internal.ads.C2889yv;
import com.google.android.gms.internal.ads.Fv;
import com.google.android.gms.internal.ads.Gv;
import com.google.android.gms.internal.ads.I7;
import com.google.android.gms.internal.ads.InterfaceC1720Kb;
import com.google.android.gms.internal.ads.InterfaceC2544qt;
import com.google.android.gms.internal.ads.Kk;
import com.google.android.gms.internal.ads.Nv;
import com.google.android.gms.internal.ads.P4;
import com.google.android.gms.internal.ads.Qv;
import com.google.android.gms.internal.ads.R7;
import com.google.android.gms.internal.ads.SharedPreferencesOnSharedPreferenceChangeListenerC2687u7;
import com.google.android.gms.internal.ads.Tq;
import com.google.android.gms.internal.ads.Uq;
import com.google.android.gms.internal.ads.zzbud;
import com.google.android.gms.internal.ads.zzbyz;
import com.google.android.gms.internal.measurement.C3083y1;
import com.google.android.gms.internal.mlkit_vision_common.W2;
import com.j256.ormlite.stmt.query.SimpleComparison;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public final class i extends AbstractBinderC1781Uc {
    public static final ArrayList H = new ArrayList(Arrays.asList("/aclk", "/pcs/click", "/dbm/clk"));
    public static final ArrayList I = new ArrayList(Arrays.asList(".doubleclick.net", ".googleadservices.com"));
    public static final ArrayList J = new ArrayList(Arrays.asList("/pagead/adview", "/pcs/view", "/pagead/conversion", "/dbm/ad"));
    public static final ArrayList K = new ArrayList(Arrays.asList(".doubleclick.net", ".googleadservices.com", ".googlesyndication.com"));
    public final ArrayList A;
    public final AtomicBoolean B;
    public final AtomicBoolean C;
    public final AtomicInteger D;
    public final I7 E;
    public final A F;
    public final v G;
    public final C1765Re b;
    public Context c;
    public final P4 d;
    public final C2067fq e;
    public final C2412nq f;
    public final C2227jd g;
    public final ScheduledExecutorService h;
    public zzbud i;
    public Point j;
    public Point k;
    public final Kk l;
    public final C2584rr m;
    public final boolean n;
    public final boolean o;
    public final boolean p;
    public final boolean q;
    public final String r;
    public final String s;
    public final AtomicInteger t;
    public final VersionInfoParcel u;
    public String v;
    public final String w;
    public final ArrayList x;
    public final ArrayList y;
    public final ArrayList z;

    public i(C1765Re c1765Re, Context context, P4 p4, C2412nq c2412nq, C2227jd c2227jd, ScheduledExecutorService scheduledExecutorService, Kk kk, C2584rr c2584rr, VersionInfoParcel versionInfoParcel, I7 i7, C2067fq c2067fq, A a, v vVar) {
        ArrayList arrayListL4;
        super("com.google.android.gms.ads.internal.signals.ISignalGenerator");
        this.j = new Point();
        this.k = new Point();
        this.t = new AtomicInteger(0);
        this.B = new AtomicBoolean(false);
        this.C = new AtomicBoolean(false);
        this.D = new AtomicInteger(0);
        this.b = c1765Re;
        this.c = context;
        this.d = p4;
        this.e = c2067fq;
        this.f = c2412nq;
        this.g = c2227jd;
        this.h = scheduledExecutorService;
        this.l = kk;
        this.m = c2584rr;
        this.u = versionInfoParcel;
        this.E = i7;
        C2601s7 c2601s7 = AbstractC2773w7.h7;
        com.google.android.gms.ads.internal.client.r rVar = com.google.android.gms.ads.internal.client.r.d;
        this.n = ((Boolean) rVar.c.a(c2601s7)).booleanValue();
        C2601s7 c2601s72 = AbstractC2773w7.g7;
        SharedPreferencesOnSharedPreferenceChangeListenerC2687u7 sharedPreferencesOnSharedPreferenceChangeListenerC2687u7 = rVar.c;
        this.o = ((Boolean) sharedPreferencesOnSharedPreferenceChangeListenerC2687u7.a(c2601s72)).booleanValue();
        this.p = ((Boolean) sharedPreferencesOnSharedPreferenceChangeListenerC2687u7.a(AbstractC2773w7.j7)).booleanValue();
        this.q = ((Boolean) sharedPreferencesOnSharedPreferenceChangeListenerC2687u7.a(AbstractC2773w7.l7)).booleanValue();
        this.r = (String) sharedPreferencesOnSharedPreferenceChangeListenerC2687u7.a(AbstractC2773w7.k7);
        this.s = (String) sharedPreferencesOnSharedPreferenceChangeListenerC2687u7.a(AbstractC2773w7.m7);
        this.w = (String) sharedPreferencesOnSharedPreferenceChangeListenerC2687u7.a(AbstractC2773w7.n7);
        this.F = a;
        this.G = vVar;
        if (((Boolean) sharedPreferencesOnSharedPreferenceChangeListenerC2687u7.a(AbstractC2773w7.o7)).booleanValue()) {
            this.x = l4((String) sharedPreferencesOnSharedPreferenceChangeListenerC2687u7.a(AbstractC2773w7.p7));
            this.y = l4((String) sharedPreferencesOnSharedPreferenceChangeListenerC2687u7.a(AbstractC2773w7.q7));
            this.z = l4((String) sharedPreferencesOnSharedPreferenceChangeListenerC2687u7.a(AbstractC2773w7.r7));
            arrayListL4 = l4((String) sharedPreferencesOnSharedPreferenceChangeListenerC2687u7.a(AbstractC2773w7.s7));
        } else {
            this.x = H;
            this.y = I;
            this.z = J;
            arrayListL4 = K;
        }
        this.A = arrayListL4;
    }

    public static boolean k4(Uri uri, ArrayList arrayList, ArrayList arrayList2) {
        String host = uri.getHost();
        String path = uri.getPath();
        if (host == null || path == null) {
            return false;
        }
        Iterator it2 = arrayList.iterator();
        while (it2.hasNext()) {
            if (path.contains((String) it2.next())) {
                Iterator it3 = arrayList2.iterator();
                while (it3.hasNext()) {
                    if (host.endsWith((String) it3.next())) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    public static final ArrayList l4(String str) {
        String[] strArrSplit = TextUtils.split(str, ",");
        ArrayList arrayList = new ArrayList();
        for (String str2 : strArrSplit) {
            if (!AbstractC2543qs.i(str2)) {
                arrayList.add(str2);
            }
        }
        return arrayList;
    }

    public static final Uri m4(Uri uri, String str, String str2) {
        String string = uri.toString();
        int iIndexOf = string.indexOf("&adurl=");
        if (iIndexOf == -1) {
            iIndexOf = string.indexOf("?adurl=");
        }
        if (iIndexOf == -1) {
            return uri.buildUpon().appendQueryParameter(str, str2).build();
        }
        int i = iIndexOf + 1;
        StringBuilder sb = new StringBuilder(string.substring(0, i));
        androidx.compose.ui.node.B.u(sb, str, SimpleComparison.EQUAL_TO_OPERATION, str2, "&");
        sb.append(string.substring(i));
        return Uri.parse(sb.toString());
    }

    public static Tq n4(com.google.common.util.concurrent.e eVar, zzbyz zzbyzVar) {
        if (!Uq.a() || !((Boolean) R7.e.o()).booleanValue()) {
            return null;
        }
        try {
            Tq tq = (Tq) ((C1925cf) AbstractC2025es.P(eVar)).a.zzb();
            tq.d(new ArrayList(Collections.singletonList(zzbyzVar.b)));
            zzm zzmVar = zzbyzVar.d;
            tq.b(zzmVar == null ? "" : zzmVar.p);
            tq.f(zzmVar.m);
            return tq;
        } catch (ExecutionException e) {
            com.google.android.gms.ads.internal.j.C.h.h("SignalGeneratorImpl.getConfiguredCriticalUserJourney", e);
            return null;
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:25:0x00be  */
    @Override // com.google.android.gms.internal.ads.InterfaceC1787Vc
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void K2(com.google.android.gms.dynamic.a r12, com.google.android.gms.internal.ads.zzbyz r13, com.google.android.gms.internal.ads.InterfaceC1769Sc r14) {
        /*
            Method dump skipped, instructions count: 290
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.ads.nonagon.signalgeneration.i.K2(com.google.android.gms.dynamic.a, com.google.android.gms.internal.ads.zzbyz, com.google.android.gms.internal.ads.Sc):void");
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Failed to restore switch over string. Please report as a decompilation issue */
    /* JADX WARN: Removed duplicated region for block: B:37:0x00c6  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final com.google.android.gms.internal.ads.C1925cf e4(android.content.Context r41, java.lang.String r42, java.lang.String r43, com.google.android.gms.ads.internal.client.zzr r44, com.google.android.gms.ads.internal.client.zzm r45, int r46, java.lang.String r47, android.os.Bundle r48, com.google.android.gms.internal.ads.zzbyz r49) {
        /*
            Method dump skipped, instructions count: 432
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.ads.nonagon.signalgeneration.i.e4(android.content.Context, java.lang.String, java.lang.String, com.google.android.gms.ads.internal.client.zzr, com.google.android.gms.ads.internal.client.zzm, int, java.lang.String, android.os.Bundle, com.google.android.gms.internal.ads.zzbyz):com.google.android.gms.internal.ads.cf");
    }

    public final Nv f4(final String str) {
        final C1843ak[] c1843akArr = new C1843ak[1];
        com.google.common.util.concurrent.e eVarA = this.f.a();
        Fv fv = new Fv() { // from class: com.google.android.gms.ads.nonagon.signalgeneration.c
            @Override // com.google.android.gms.internal.ads.Fv
            public final com.google.common.util.concurrent.e b(Object obj) throws JSONException {
                C1843ak c1843ak = (C1843ak) obj;
                c1843akArr[0] = c1843ak;
                i iVar = this.a;
                Context context = iVar.c;
                zzbud zzbudVar = iVar.i;
                Map map = zzbudVar.b;
                JSONObject jSONObjectE = W2.e(context, map, map, zzbudVar.a, null);
                JSONObject jSONObjectI = W2.i(iVar.c, iVar.i.a);
                JSONObject jSONObjectH = W2.h(iVar.i.a);
                JSONObject jSONObjectF = W2.f(iVar.c, iVar.i.a);
                JSONObject jSONObject = new JSONObject();
                jSONObject.put("asset_view_signal", jSONObjectE);
                jSONObject.put("ad_view_signal", jSONObjectI);
                jSONObject.put("scroll_view_signal", jSONObjectH);
                jSONObject.put("lock_screen_signal", jSONObjectF);
                String str2 = str;
                if ("google.afma.nativeAds.getPublisherCustomRenderedClickSignals".equals(str2)) {
                    jSONObject.put("click_signal", W2.d(null, iVar.c, iVar.k, iVar.j));
                }
                return c1843ak.a(str2, jSONObject);
            }
        };
        C2227jd c2227jd = this.g;
        C2846xv c2846xvN = AbstractC2025es.N(eVarA, fv, c2227jd);
        c2846xvN.a(new androidx.camera.core.impl.utils.futures.h(18, this, c1843akArr), c2227jd);
        final int i = 0;
        C2889yv c2889yvL = AbstractC2025es.L((Nv) AbstractC2025es.O(Nv.t(c2846xvN), ((Integer) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.F7)).intValue(), TimeUnit.MILLISECONDS, this.h), new InterfaceC2544qt() { // from class: com.google.android.gms.ads.nonagon.signalgeneration.g
            @Override // com.google.android.gms.internal.ads.InterfaceC2544qt
            public final Object apply(Object obj) {
                switch (i) {
                    case 0:
                        ArrayList arrayList = i.H;
                        return ((JSONObject) obj).optString("nas");
                    default:
                        ArrayList arrayList2 = i.H;
                        com.google.android.gms.ads.internal.util.client.i.f("", (Exception) obj);
                        return null;
                }
            }
        }, c2227jd);
        final int i2 = 1;
        return AbstractC2025es.x(c2889yvL, Exception.class, new InterfaceC2544qt() { // from class: com.google.android.gms.ads.nonagon.signalgeneration.g
            @Override // com.google.android.gms.internal.ads.InterfaceC2544qt
            public final Object apply(Object obj) {
                switch (i2) {
                    case 0:
                        ArrayList arrayList = i.H;
                        return ((JSONObject) obj).optString("nas");
                    default:
                        ArrayList arrayList2 = i.H;
                        com.google.android.gms.ads.internal.util.client.i.f("", (Exception) obj);
                        return null;
                }
            }
        }, c2227jd);
    }

    public final void g4() {
        i iVar;
        com.google.common.util.concurrent.e eVarI;
        if (((Boolean) AbstractC1911c8.e.o()).booleanValue()) {
            A a = this.F;
            synchronized (a) {
                a.c(true);
                a.c(false);
            }
            return;
        }
        if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.cb)).booleanValue()) {
            eVarI = AbstractC2025es.I(new com.airbnb.lottie.network.d(this, 23), AbstractC2270kd.a);
            iVar = this;
        } else {
            iVar = this;
            eVarI = (com.google.common.util.concurrent.e) iVar.e4(this.c, null, "BANNER", null, null, 0, null, new Bundle(), null).b.zzb();
        }
        com.google.android.gms.auth.api.signin.internal.h hVar = new com.google.android.gms.auth.api.signin.internal.h(this, 22);
        eVarI.a(new Qv(0, eVarI, hVar), iVar.b.a());
    }

    public final void h4() {
        C2601s7 c2601s7 = AbstractC2773w7.C9;
        com.google.android.gms.ads.internal.client.r rVar = com.google.android.gms.ads.internal.client.r.d;
        if (((Boolean) rVar.c.a(c2601s7)).booleanValue()) {
            C2601s7 c2601s72 = AbstractC2773w7.F9;
            SharedPreferencesOnSharedPreferenceChangeListenerC2687u7 sharedPreferencesOnSharedPreferenceChangeListenerC2687u7 = rVar.c;
            if (((Boolean) sharedPreferencesOnSharedPreferenceChangeListenerC2687u7.a(c2601s72)).booleanValue()) {
                return;
            }
            if (((Boolean) sharedPreferencesOnSharedPreferenceChangeListenerC2687u7.a(AbstractC2773w7.J9)).booleanValue() && this.B.getAndSet(true)) {
                return;
            }
            g4();
        }
    }

    public final void i4(ArrayList arrayList, com.google.android.gms.dynamic.a aVar, InterfaceC1720Kb interfaceC1720Kb, boolean z) {
        ArrayList arrayList2;
        ArrayList arrayList3;
        com.google.common.util.concurrent.e eVarN;
        Map map;
        if (!((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.E7)).booleanValue()) {
            com.google.android.gms.ads.internal.util.client.i.h("The updating URL feature is not enabled.");
            try {
                C1708Ib c1708Ib = (C1708Ib) interfaceC1720Kb;
                Parcel parcelF3 = c1708Ib.f3();
                parcelF3.writeString("The updating URL feature is not enabled.");
                c1708Ib.d4(2, parcelF3);
                return;
            } catch (RemoteException e) {
                com.google.android.gms.ads.internal.util.client.i.f("", e);
                return;
            }
        }
        Iterator it2 = arrayList.iterator();
        int i = 0;
        while (true) {
            boolean zHasNext = it2.hasNext();
            arrayList2 = this.y;
            arrayList3 = this.x;
            if (!zHasNext) {
                break;
            } else if (k4((Uri) it2.next(), arrayList3, arrayList2)) {
                i++;
            }
        }
        if (i > 1) {
            com.google.android.gms.ads.internal.util.client.i.h("Multiple google urls found: ".concat(String.valueOf(arrayList)));
        }
        ArrayList arrayList4 = new ArrayList();
        Iterator it3 = arrayList.iterator();
        while (it3.hasNext()) {
            Uri uri = (Uri) it3.next();
            if (k4(uri, arrayList3, arrayList2)) {
                com.android.billingclient.api.n nVar = new com.android.billingclient.api.n(this, uri, aVar, 4);
                C2227jd c2227jd = this.g;
                com.google.common.util.concurrent.e eVarD = c2227jd.d(nVar);
                zzbud zzbudVar = this.i;
                if (zzbudVar == null || (map = zzbudVar.b) == null || map.isEmpty()) {
                    com.google.android.gms.ads.internal.util.client.i.g("Asset view map is empty.");
                    eVarN = eVarD;
                } else {
                    eVarN = AbstractC2025es.N(eVarD, new C1638d(this, 0), c2227jd);
                }
            } else {
                com.google.android.gms.ads.internal.util.client.i.h("Not a Google URL: ".concat(String.valueOf(uri)));
                eVarN = AbstractC2025es.E(uri);
            }
            arrayList4.add(eVarN);
        }
        Gv gv = new Gv(AbstractC2330lu.n(arrayList4), true);
        gv.a(new Qv(0, gv, new C3083y1(this, interfaceC1720Kb, z)), this.b.a());
    }

    public final void j4(ArrayList arrayList, com.google.android.gms.dynamic.a aVar, InterfaceC1720Kb interfaceC1720Kb, boolean z) {
        Map map;
        if (!((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.E7)).booleanValue()) {
            try {
                C1708Ib c1708Ib = (C1708Ib) interfaceC1720Kb;
                Parcel parcelF3 = c1708Ib.f3();
                parcelF3.writeString("The updating URL feature is not enabled.");
                c1708Ib.d4(2, parcelF3);
                return;
            } catch (RemoteException e) {
                com.google.android.gms.ads.internal.util.client.i.f("", e);
                return;
            }
        }
        com.android.billingclient.api.n nVar = new com.android.billingclient.api.n(this, arrayList, aVar, 5);
        C2227jd c2227jd = this.g;
        com.google.common.util.concurrent.e eVarD = c2227jd.d(nVar);
        zzbud zzbudVar = this.i;
        if (zzbudVar == null || (map = zzbudVar.b) == null || map.isEmpty()) {
            com.google.android.gms.ads.internal.util.client.i.g("Asset view map is empty.");
        } else {
            eVarD = AbstractC2025es.N(eVarD, new C1638d(this, 1), c2227jd);
        }
        eVarD.a(new Qv(0, eVarD, new com.bumptech.glide.manager.p(this, interfaceC1720Kb, z)), this.b.a());
    }
}

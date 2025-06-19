package com.google.android.gms.internal.ads;

import android.content.Context;
import android.net.TrafficStats;
import android.net.Uri;
import android.os.StrictMode;
import com.comscore.streaming.EventType;
import com.google.android.gms.ads.internal.client.InterfaceC1582a;
import com.google.android.gms.ads.internal.util.client.VersionInfoParcel;
import java.io.ByteArrayInputStream;
import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import org.json.JSONArray;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public final class L9 implements com.google.android.gms.ads.initialization.a, InterfaceC2356md, InterfaceC2399nd, InterfaceC2139ha, InterfaceC2183ia, com.google.android.gms.ads.mediation.b, com.google.android.gms.ads.mediation.rtb.b, com.google.android.gms.ads.nativead.e, InterfaceC1750Pb, X, Pv, Xh {
    public final /* synthetic */ int a;

    public /* synthetic */ L9(int i) {
        this.a = i;
    }

    public static final InterfaceC2529qe g(final Context context, final androidx.work.impl.model.c cVar, final com.bumptech.glide.load.engine.cache.f fVar, final VersionInfoParcel versionInfoParcel, final P4 p4, final C2429o6 c2429o6, final J7 j7, final Hk hk, final BinderC2408nm binderC2408nm, final C2881yn c2881yn, final Vp vp, final Xp xp, final C2067fq c2067fq, final String str, final boolean z, final boolean z2) {
        AbstractC2773w7.a(context);
        try {
            Bt bt = new Bt() { // from class: com.google.android.gms.internal.ads.te
                @Override // com.google.android.gms.internal.ads.Bt
                public final Object zza() {
                    com.bumptech.glide.load.engine.cache.f fVar2 = fVar;
                    String str2 = str;
                    boolean z3 = z;
                    C2429o6 c2429o62 = c2429o6;
                    boolean z4 = z2;
                    P4 p42 = p4;
                    Vp vp2 = vp;
                    J7 j72 = j7;
                    C2881yn c2881yn2 = c2881yn;
                    Xp xp2 = xp;
                    Context context2 = context;
                    VersionInfoParcel versionInfoParcel2 = versionInfoParcel;
                    androidx.work.impl.model.c cVar2 = cVar;
                    C2067fq c2067fq2 = c2067fq;
                    Hk hk2 = hk;
                    BinderC2408nm binderC2408nm2 = binderC2408nm;
                    try {
                        TrafficStats.setThreadStatsTag(264);
                        int i = ViewTreeObserverOnGlobalLayoutListenerC2829xe.m1;
                        C2743ve c2743ve = new C2743ve(new ViewTreeObserverOnGlobalLayoutListenerC2829xe(new C1693Fe(context2), fVar2, str2, z3, p42, j72, versionInfoParcel2, c2881yn2, cVar2, c2429o62, vp2, xp2, c2067fq2), hk2);
                        com.google.android.gms.ads.internal.j.C.f.getClass();
                        c2743ve.setWebViewClient(new C1669Be(c2743ve, c2429o62, z4, new C2526qb(c2743ve, c2743ve.J(), new C2558r7(c2743ve.getContext())), binderC2408nm2));
                        c2743ve.setWebChromeClient(new C2486pe(c2743ve));
                        return c2743ve;
                    } finally {
                        TrafficStats.clearThreadStatsTag();
                    }
                }
            };
            StrictMode.ThreadPolicy threadPolicy = StrictMode.getThreadPolicy();
            try {
                StrictMode.setThreadPolicy(new StrictMode.ThreadPolicy.Builder(threadPolicy).permitDiskReads().permitDiskWrites().build());
                Object objZza = bt.zza();
                StrictMode.setThreadPolicy(threadPolicy);
                return (InterfaceC2529qe) objZza;
            } catch (Throwable th) {
                StrictMode.setThreadPolicy(threadPolicy);
                throw th;
            }
        } catch (Throwable th2) {
            throw new zzcfn("Webview initialization failed.", th2);
        }
    }

    public static final void h(String str, JSONObject jSONObject) {
        JSONArray jSONArrayOptJSONArray = jSONObject.optJSONArray(str);
        if (jSONArrayOptJSONArray != null) {
            ArrayList arrayList = new ArrayList(jSONArrayOptJSONArray.length());
            for (int i = 0; i < jSONArrayOptJSONArray.length(); i++) {
                arrayList.add(jSONArrayOptJSONArray.getString(i));
            }
            Collections.unmodifiableList(arrayList);
        }
    }

    private final void i() {
    }

    private final void j() {
    }

    @Override // com.google.android.gms.internal.ads.X
    public U[] a(Uri uri, Map map) {
        switch (this.a) {
            case EventType.VIDEO /* 24 */:
                AtomicInteger atomicInteger = C2143he.u;
                return new U[]{new F1(), new C2295l1()};
            default:
                AtomicInteger atomicInteger2 = C2143he.u;
                return new U[]{new F1(), new C2295l1(), new B1(Z1.P0, 32, Bu.e)};
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2399nd
    /* renamed from: b */
    public void mo21b(Object obj) {
        switch (this.a) {
            case 3:
                com.google.android.gms.ads.internal.util.A.l("Ending javascript session.");
                C2095ga c2095ga = (C2095ga) ((InterfaceC2051fa) obj);
                HashSet hashSet = c2095ga.b;
                Iterator it2 = hashSet.iterator();
                while (it2.hasNext()) {
                    AbstractMap.SimpleEntry simpleEntry = (AbstractMap.SimpleEntry) it2.next();
                    com.google.android.gms.ads.internal.util.A.l("Unregistering eventhandler: ".concat(String.valueOf(((InterfaceC2389n9) simpleEntry.getValue()).toString())));
                    c2095ga.a.o((String) simpleEntry.getKey(), (InterfaceC2389n9) simpleEntry.getValue());
                }
                hashSet.clear();
                break;
            case 4:
                AbstractC2270kd.f.execute(new X9((V9) obj, 2));
                break;
            default:
                ((InterfaceC1582a) obj).onAdClicked();
                break;
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2183ia
    public /* bridge */ /* synthetic */ JSONObject c(Object obj) {
        return (JSONObject) obj;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1750Pb
    public void d(String str, Throwable th) {
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1750Pb
    public void e(Throwable th, String str, float f) {
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2139ha
    public Object f(JSONObject jSONObject) {
        switch (this.a) {
            case 5:
                return new ByteArrayInputStream(jSONObject.toString().getBytes(AbstractC2224ja.a));
            default:
                return jSONObject;
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2356md, com.google.android.gms.internal.ads.Hq
    /* renamed from: zza */
    public void mo13zza() {
        int i = this.a;
    }

    @Override // com.google.android.gms.internal.ads.Pv
    /* renamed from: c, reason: collision with other method in class */
    public /* synthetic */ void mo15c(Object obj) {
        ((AbstractC2359mg) obj).p();
    }

    @Override // com.google.android.gms.internal.ads.Pv
    public void zza(Throwable th) {
    }
}

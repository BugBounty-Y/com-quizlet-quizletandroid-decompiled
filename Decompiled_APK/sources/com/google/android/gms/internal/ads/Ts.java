package com.google.android.gms.internal.ads;

import android.content.Context;
import android.database.sqlite.SQLiteDatabase;
import android.os.DeadObjectException;
import android.os.Handler;
import android.os.RemoteException;
import android.os.SystemClock;
import android.view.MotionEvent;
import android.view.Surface;
import com.comscore.streaming.EventType;
import com.google.android.gms.ads.nativead.NativeCustomFormatAd;
import com.google.android.gms.common.internal.InterfaceC1652b;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import kotlin.jvm.internal.Intrinsics;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public final class Ts implements D, InterfaceC2512q3, InterfaceC2843xs, InterfaceC1652b, Pv, InterfaceC2399nd, InterfaceC2356md, com.google.android.gms.ads.mediation.c, Gq, Xh, InterfaceC1681De, InterfaceC2517q8, Ol, Ai, Rn, Dp {
    public static Ts c;
    public final /* synthetic */ int a;
    public Object b;

    public /* synthetic */ Ts() {
        this.a = 26;
    }

    public static final Ts j(Context context) {
        Ts ts;
        synchronized (Ts.class) {
            try {
                if (c == null) {
                    c = new Ts(context);
                }
                ts = c;
            } catch (Throwable th) {
                throw th;
            }
        }
        return ts;
    }

    private final void m(Throwable th) {
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1681De
    public void A(String str, int i, String str2, boolean z) {
        C2257k6 c2257k6 = (C2257k6) this.b;
        if (z) {
            c2257k6.e();
            return;
        }
        c2257k6.d(new zzegy(1, "Image Web View failed to load. Error code: " + i + ", Description: " + str + ", Failing URL: " + str2));
    }

    @Override // com.google.android.gms.common.internal.InterfaceC1652b
    public void V(int i) {
        C2084g6 c2084g6 = (C2084g6) this.b;
        synchronized (c2084g6.c) {
            c2084g6.f = null;
            c2084g6.c.notifyAll();
        }
    }

    @Override // com.google.android.gms.common.internal.InterfaceC1652b
    public void X() {
        C2172i6 c2172i6;
        C2084g6 c2084g6 = (C2084g6) this.b;
        synchronized (c2084g6.c) {
            try {
                c2172i6 = (C2172i6) c2084g6.d;
            } catch (DeadObjectException e) {
                com.google.android.gms.ads.internal.util.client.i.f("Unable to obtain a cache service instance.", e);
                C2084g6.p((C2084g6) this.b);
            }
            if (c2172i6 != null) {
                c2084g6.f = (C2214j6) c2172i6.m();
                ((C2084g6) this.b).c.notifyAll();
            } else {
                ((C2084g6) this.b).c.notifyAll();
            }
        }
    }

    @Override // com.google.android.gms.internal.ads.D
    public void a() {
        switch (this.a) {
            case 1:
                C2293l c2293l = (C2293l) this.b;
                if (c2293l.U1 != null) {
                    c2293l.l0(0, 1);
                    return;
                }
                return;
            default:
                Ui ui = ((Uj) this.b).d;
                if (ui != null) {
                    synchronized (ui) {
                        ui.l.T(NativeCustomFormatAd.ASSET_NAME_VIDEO);
                    }
                    return;
                }
                return;
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r2v5, types: [int] */
    /* JADX WARN: Type inference failed for: r2v6 */
    /* JADX WARN: Type inference failed for: r2v7 */
    /* JADX WARN: Type inference failed for: r3v8, types: [com.google.android.gms.internal.ads.Gc] */
    @Override // com.google.android.gms.internal.ads.Gq
    public Object b(Object obj) {
        C1849aq c1849aq = (C1849aq) obj;
        C2272kf c2272kf = ((C2831xg) this.b).d;
        Iterator it2 = ((ArrayList) c1849aq.b.c).iterator();
        while (it2.hasNext()) {
            Zp zp = (Zp) it2.next();
            String str = zp.a;
            Map map = c2272kf.a;
            boolean zContainsKey = map.containsKey(str);
            JSONObject jSONObject = zp.b;
            if (zContainsKey && jSONObject != null) {
                C2572rf c2572rf = (C2572rf) map.get(str);
                switch (c2572rf.a) {
                    case 0:
                        if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.k9)).booleanValue()) {
                            C2493pl c2493pl = (C2493pl) c2572rf.b;
                            synchronized (c2493pl) {
                                c2493pl.p = jSONObject;
                            }
                            break;
                        } else {
                            continue;
                        }
                    default:
                        ((C1697Gc) ((Fi) c2572rf.b).c).a(jSONObject.optBoolean("npa_reset") ? -1 : jSONObject.optBoolean("npa"), jSONObject.optLong("timestamp"));
                        break;
                }
            } else {
                Map map2 = c2272kf.b;
                if (map2.containsKey(str) && jSONObject != null) {
                    InterfaceC2315lf interfaceC2315lf = (InterfaceC2315lf) map2.get(str);
                    HashMap map3 = new HashMap();
                    Iterator<String> itKeys = jSONObject.keys();
                    while (itKeys.hasNext()) {
                        String next = itKeys.next();
                        String strOptString = jSONObject.optString(next);
                        if (strOptString != null) {
                            map3.put(next, strOptString);
                        }
                    }
                    interfaceC2315lf.a(map3);
                }
            }
        }
        return c1849aq;
    }

    @Override // com.google.android.gms.internal.ads.Pv
    /* renamed from: c */
    public void mo15c(Object obj) {
        C2313ld c2313ld;
        switch (this.a) {
            case 7:
                String str = (String) obj;
                InterfaceC2529qe interfaceC2529qe = (InterfaceC2529qe) this.b;
                new com.google.android.gms.ads.internal.util.t(interfaceC2529qe.getContext(), interfaceC2529qe.l().a, str, interfaceC2529qe.e() != null ? interfaceC2529qe.e().x0 : null).R();
                return;
            case 12:
                C1673Cc.l.remove((com.google.common.util.concurrent.e) this.b);
                return;
            case 13:
                ((AtomicInteger) ((androidx.appcompat.app.y) this.b).c).set(1);
                return;
            case 19:
                InterfaceC2529qe interfaceC2529qe2 = (InterfaceC2529qe) obj;
                Ui ui = (Ui) this.b;
                Yi yi = ui.k;
                synchronized (yi) {
                    yi.k = interfaceC2529qe2;
                }
                Yi yi2 = ui.k;
                synchronized (yi2) {
                    c2313ld = yi2.n;
                }
                C2665tm c2665tmS = ui.s("Google", true);
                if (c2665tmS != null && c2313ld != null) {
                    c2313ld.c(c2665tmS);
                    return;
                } else {
                    if (c2313ld != null) {
                        c2313ld.cancel(false);
                        return;
                    }
                    return;
                }
            case EventType.WINDOW_STATE /* 22 */:
                C1849aq c1849aq = (C1849aq) obj;
                if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.m2)).booleanValue()) {
                    ((Dl) this.b).k.J0(c1849aq);
                    return;
                }
                return;
            default:
                try {
                    ((Gq) this.b).b((SQLiteDatabase) obj);
                    return;
                } catch (Exception e) {
                    com.google.android.gms.ads.internal.util.client.i.e("Error executing function on offline signal database: ".concat(String.valueOf(e.getMessage())));
                    return;
                }
        }
    }

    @Override // com.google.android.gms.internal.ads.Ol
    public com.google.common.util.concurrent.e d(zzbvl zzbvlVar) {
        return ((Tl) ((InterfaceC2907zC) ((C2326lq) this.b).d).zzb()).h4(zzbvlVar.h);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2843xs
    public void e(int i, long j) {
        ((androidx.browser.customtabs.k) this.b).s(i, System.currentTimeMillis() - j);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2843xs
    public void f(int i, long j, String str) {
        ((androidx.browser.customtabs.k) this.b).u(i, System.currentTimeMillis() - j, null, null, str);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2517q8
    public void g(MotionEvent motionEvent) {
    }

    @Override // com.google.android.gms.internal.ads.Dp
    public Pg h(Cp cp) {
        return ((C2454op) this.b).b(cp);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2512q3
    public void i(MessageDigest[] messageDigestArr, long j, int i) {
        ByteBuffer byteBufferSlice;
        ByteBuffer byteBuffer = (ByteBuffer) this.b;
        synchronized (byteBuffer) {
            int i2 = (int) j;
            byteBuffer.position(i2);
            byteBuffer.limit(i2 + i);
            byteBufferSlice = byteBuffer.slice();
        }
        for (MessageDigest messageDigest : messageDigestArr) {
            byteBufferSlice.position(0);
            messageDigest.update(byteBufferSlice);
        }
    }

    @Override // com.google.android.gms.internal.ads.Ai
    public void k(boolean z, Context context, C2058fh c2058fh) {
    }

    public com.google.common.util.concurrent.e l(boolean z) {
        try {
            Intrinsics.checkNotNullParameter("com.google.android.gms.ads", "adsSdkName");
            androidx.privacysandbox.ads.adservices.topics.a aVar = new androidx.privacysandbox.ads.adservices.topics.a(z);
            androidx.privacysandbox.ads.adservices.java.topics.b bVarA = androidx.privacysandbox.ads.adservices.java.topics.b.a((Context) this.b);
            return bVarA != null ? bVarA.b(aVar) : AbstractC2025es.C(new IllegalStateException());
        } catch (Exception e) {
            return AbstractC2025es.C(e);
        }
    }

    public void n() {
        synchronized (Ts.class) {
            Ps ps = (Ps) this.b;
            ps.v("vendor_scoped_gpid_v2_id");
            ps.v("vendor_scoped_gpid_v2_creation_time");
        }
    }

    @Override // com.google.android.gms.internal.ads.Rn
    public /* bridge */ /* synthetic */ void o(AbstractC2359mg abstractC2359mg) {
        On on = (On) this.b;
        C2747vi c2747vi = (C2747vi) abstractC2359mg;
        synchronized (on) {
            on.j = c2747vi;
            c2747vi.a();
        }
    }

    @Override // com.google.android.gms.ads.mediation.c
    public void s(com.google.android.gms.ads.b bVar) {
        switch (this.a) {
            case 10:
                try {
                    ((InterfaceC1779Ua) this.b).r(bVar.a());
                    break;
                } catch (RemoteException e) {
                    com.google.android.gms.ads.internal.util.client.i.f("", e);
                    return;
                }
            default:
                try {
                    ((InterfaceC1767Sa) this.b).r(bVar.a());
                    break;
                } catch (RemoteException e2) {
                    com.google.android.gms.ads.internal.util.client.i.f("", e2);
                }
        }
    }

    @Override // com.google.android.gms.internal.ads.Ai
    /* renamed from: zza */
    public Vp mo17zza() {
        return (Vp) this.b;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2517q8
    public JSONObject zzb() {
        return null;
    }

    public /* synthetic */ Ts(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2517q8
    /* renamed from: zza */
    public JSONObject mo12zza() {
        return null;
    }

    public Ts(Context context) {
        this.a = 0;
        if (Ps.c == null) {
            Ps.c = new Ps(context);
        }
        this.b = Ps.c;
        Os.e(context);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2512q3
    public long zza() {
        return ((ByteBuffer) this.b).capacity();
    }

    @Override // com.google.android.gms.internal.ads.D
    /* renamed from: zza */
    public void mo11zza() {
        switch (this.a) {
            case 1:
                C2293l c2293l = (C2293l) this.b;
                Surface surface = c2293l.U1;
                if (surface != null) {
                    Fi fi = c2293l.H1;
                    Handler handler = (Handler) fi.b;
                    if (handler != null) {
                        handler.post(new com.android.volley.i(fi, surface, SystemClock.elapsedRealtime(), 1, false));
                    }
                    c2293l.X1 = true;
                    return;
                }
                return;
            case 9:
                com.google.android.gms.ads.internal.util.A.l("Rejecting reference for JS Engine.");
                boolean zBooleanValue = ((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.J7)).booleanValue();
                C1920ca c1920ca = (C1920ca) this.b;
                if (zBooleanValue) {
                    c1920ca.t("SdkJavascriptFactory.createNewReference.FailureCallback", new IllegalStateException("Unable to create JS engine reference."));
                    return;
                } else {
                    c1920ca.s();
                    return;
                }
            default:
                On on = (On) this.b;
                synchronized (on) {
                    on.j = null;
                }
                return;
        }
    }

    public Ts(ByteBuffer byteBuffer) {
        this.a = 4;
        this.b = byteBuffer.slice();
    }

    @Override // com.google.android.gms.internal.ads.Pv
    public void zza(Throwable th) {
        switch (this.a) {
            case 7:
                com.google.android.gms.ads.internal.j.C.h.h("DefaultGmsgHandlers.attributionReportingManager", th);
                break;
            case 12:
                C1673Cc.l.remove((com.google.common.util.concurrent.e) this.b);
                break;
            case 13:
                ((AtomicInteger) ((androidx.appcompat.app.y) this.b).c).set(-1);
                break;
            case 19:
                if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.s5)).booleanValue()) {
                    com.google.android.gms.ads.internal.j.C.h.g("omid native display exp", th);
                    break;
                }
                break;
            case EventType.WINDOW_STATE /* 22 */:
                break;
            default:
                com.google.android.gms.ads.internal.util.client.i.e("Failed to get offline signal database: ".concat(String.valueOf(th.getMessage())));
                break;
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2399nd
    /* renamed from: b */
    public void mo21b(Object obj) {
        switch (this.a) {
            case 8:
                if (((V9) obj).a.B()) {
                    ((C2007ea) this.b).b = 1;
                    break;
                }
                break;
            case 17:
                ((Uh) obj).T0((T6) this.b);
                break;
            default:
                ((E5) obj).R0((D5) this.b);
                break;
        }
    }
}

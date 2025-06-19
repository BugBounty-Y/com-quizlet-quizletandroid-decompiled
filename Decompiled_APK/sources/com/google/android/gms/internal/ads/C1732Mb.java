package com.google.android.gms.internal.ads;

import android.content.ContentValues;
import android.content.Context;
import android.database.sqlite.SQLiteDatabase;
import android.os.Bundle;
import android.os.DeadObjectException;
import android.os.Parcel;
import android.os.RemoteException;
import android.view.View;
import androidx.compose.material3.C0591b1;
import com.amazon.device.ads.DTBMetricsConfiguration;
import com.comscore.streaming.EventType;
import com.google.android.gms.ads.internal.client.C1590e;
import com.google.android.gms.ads.internal.client.C1608n;
import com.google.android.gms.ads.internal.client.C1614q;
import com.google.android.gms.ads.internal.client.zze;
import com.google.android.gms.ads.internal.client.zzm;
import com.google.android.gms.ads.internal.util.zzbb;
import com.google.android.gms.common.internal.InterfaceC1652b;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

/* renamed from: com.google.android.gms.internal.ads.Mb, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public class C1732Mb implements InterfaceC1818a2, InterfaceC2037f3, InterfaceC2855y3, K3, InterfaceC1652b, com.google.android.gms.ads.mediation.c, InterfaceC2589rw, Pv, Xh, InterfaceC1681De, Gq, Ai, Hq {
    public static InterfaceC1787Vc d;
    public final /* synthetic */ int a;
    public Object b;
    public Object c;

    public /* synthetic */ C1732Mb(int i, Object obj, Object obj2) {
        this.a = i;
        this.b = obj;
        this.c = obj2;
    }

    private final void h(Throwable th) {
    }

    private final void i(Throwable th) {
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1681De
    public void A(String str, int i, String str2, boolean z) {
        switch (this.a) {
            case 20:
                HashMap map = new HashMap();
                map.put("messageType", "htmlLoaded");
                map.put("id", (String) ((Map) this.c).get("id"));
                ((C2534qj) this.b).b.b(map);
                break;
            default:
                C2313ld c2313ld = (C2313ld) this.c;
                if (!z) {
                    c2313ld.d(new Exception("Ad Web View failed to load. Error code: " + i + ", Description: " + str + ", Failing URL: " + str2));
                    break;
                } else {
                    if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.k2)).booleanValue()) {
                        com.google.android.gms.ads.internal.j.C.k.getClass();
                        ((Bundle) this.b).putLong("rendering-webview-load-html-end", System.currentTimeMillis());
                    }
                    c2313ld.c(null);
                    break;
                }
        }
    }

    @Override // com.google.android.gms.common.internal.InterfaceC1652b
    public void V(int i) {
        ((C2313ld) this.b).d(new RuntimeException(android.support.v4.media.session.a.f(i, "onConnectionSuspended: ")));
    }

    @Override // com.google.android.gms.common.internal.InterfaceC1652b
    public void X() {
        try {
            ((C2313ld) this.b).c((B9) ((F9) this.c).a.m());
        } catch (DeadObjectException e) {
            ((C2313ld) this.b).d(e);
        }
    }

    /* JADX WARN: Code restructure failed: missing block: B:204:0x03aa, code lost:
    
        r0.addAll(r12);
     */
    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:126:0x0253  */
    /* JADX WARN: Removed duplicated region for block: B:128:0x025e  */
    /* JADX WARN: Removed duplicated region for block: B:187:0x0365  */
    /* JADX WARN: Removed duplicated region for block: B:189:0x0368  */
    /* JADX WARN: Removed duplicated region for block: B:197:0x037d  */
    /* JADX WARN: Removed duplicated region for block: B:219:0x03ef  */
    /* JADX WARN: Removed duplicated region for block: B:222:0x03f9  */
    /* JADX WARN: Removed duplicated region for block: B:38:0x00bc  */
    /* JADX WARN: Removed duplicated region for block: B:95:0x01e0 A[PHI: r3
  0x01e0: PHI (r3v6 int) = (r3v5 int), (r3v5 int), (r3v5 int), (r3v28 int) binds: [B:92:0x01ce, B:94:0x01de, B:98:0x01ee, B:127:0x025c] A[DONT_GENERATE, DONT_INLINE]] */
    /* JADX WARN: Type inference failed for: r6v11 */
    /* JADX WARN: Type inference failed for: r6v13 */
    /* JADX WARN: Type inference failed for: r6v2 */
    /* JADX WARN: Type inference failed for: r6v30 */
    /* JADX WARN: Type inference failed for: r6v8, types: [boolean] */
    /* JADX WARN: Type inference failed for: r6v9 */
    @Override // com.google.android.gms.internal.ads.InterfaceC1818a2
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void a(byte[] r20, int r21, int r22, androidx.camera.core.impl.C0186z r23) throws com.google.android.gms.internal.ads.zzaz {
        /*
            Method dump skipped, instructions count: 1069
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.C1732Mb.a(byte[], int, int, androidx.camera.core.impl.z):void");
    }

    @Override // com.google.android.gms.internal.ads.Gq
    public Object b(Object obj) throws IllegalAccessException, InstantiationException, IllegalArgumentException, InvocationTargetException {
        switch (this.a) {
            case EventType.SUBS /* 25 */:
                return j((Ul) obj);
            default:
                ContentValues contentValues = new ContentValues();
                com.android.volley.toolbox.d dVar = (com.android.volley.toolbox.d) this.c;
                contentValues.put("timestamp", Long.valueOf(dVar.b));
                contentValues.put("gws_query_id", (String) dVar.a);
                contentValues.put(DTBMetricsConfiguration.APSMETRICS_URL, (String) dVar.d);
                contentValues.put("event_state", Integer.valueOf(dVar.c - 1));
                ((SQLiteDatabase) obj).insert("offline_buffered_pings", null, contentValues);
                com.google.android.gms.ads.internal.util.F f = com.google.android.gms.ads.internal.j.C.c;
                Context context = ((C2107gm) this.b).a;
                com.google.android.gms.ads.internal.util.s sVarA = com.google.android.gms.ads.internal.util.F.a(context);
                if (sVarA != null) {
                    try {
                        sVarA.zze(new com.google.android.gms.dynamic.b(context));
                    } catch (RemoteException unused) {
                        com.google.android.gms.ads.internal.util.A.m();
                    }
                }
                return null;
        }
    }

    @Override // com.google.android.gms.internal.ads.Pv
    /* renamed from: c */
    public void mo15c(Object obj) {
        switch (this.a) {
            case 15:
                String str = (String) obj;
                C1682Df c1682Df = (C1682Df) this.c;
                C2155hq c2155hq = c1682Df.h;
                List listJ = c1682Df.j();
                c2155hq.a(c1682Df.g.c(c1682Df.e, c1682Df.f, false, (String) this.b, str, listJ), c1682Df.n);
                return;
            case 16:
            case 18:
            case 20:
            case EventType.WINDOW_STATE /* 22 */:
            default:
                com.google.android.datatransport.cct.internal.s sVar = (com.google.android.datatransport.cct.internal.s) this.c;
                InterfaceC2237jn interfaceC2237jn = (InterfaceC2237jn) obj;
                synchronized (sVar) {
                    ((C1890bn) sVar.h).c(interfaceC2237jn, (Vp) this.b);
                    Vp vpA = ((C1890bn) sVar.h).a();
                    if (vpA != null) {
                        sVar.u(vpA);
                    }
                }
                return;
            case 17:
                AbstractC2270kd.f.execute(new RunnableC1989e((C2659tg) this.c, 25));
                ((com.quizlet.remote.model.notes.e) this.b).mo15c((AbstractC2359mg) obj);
                return;
            case 19:
                ((Ui) this.c).n((View) this.b, (C2665tm) obj);
                return;
            case 21:
                ((InterfaceC2529qe) obj).O0((String) this.b, (InterfaceC2389n9) this.c);
                return;
            case EventType.AUDIO /* 23 */:
                ((C2150hl) obj).m = true;
                ((BinderC2707ul) this.c).d.b((String) this.b);
                return;
            case EventType.VIDEO /* 24 */:
                String str2 = (String) obj;
                try {
                    C1798Xb c1798Xb = (C1798Xb) this.c;
                    zzbuv zzbuvVar = (zzbuv) this.b;
                    Parcel parcelF3 = c1798Xb.f3();
                    parcelF3.writeString(str2);
                    AbstractC2857y5.c(parcelF3, zzbuvVar);
                    c1798Xb.d4(1, parcelF3);
                    return;
                } catch (RemoteException unused) {
                    com.google.android.gms.ads.internal.util.A.m();
                    return;
                }
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2037f3
    public void d(Kn kn) {
        if (kn.z() != 0 || (kn.z() & 128) == 0) {
            return;
        }
        kn.k(6);
        int iS = kn.s() / 4;
        int i = 0;
        while (true) {
            C2125h3 c2125h3 = (C2125h3) this.c;
            if (i >= iS) {
                c2125h3.f.remove(0);
                return;
            }
            C2466p0 c2466p0 = (C2466p0) this.b;
            kn.f(0, c2466p0.b, 4);
            c2466p0.s(0);
            int iF = c2466p0.f(16);
            c2466p0.u(3);
            if (iF == 0) {
                c2466p0.u(13);
            } else {
                int iF2 = c2466p0.f(13);
                if (c2125h3.f.get(iF2) == null) {
                    c2125h3.f.put(iF2, new C2081g3(new YF(c2125h3, iF2)));
                }
            }
            i++;
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2037f3
    public void e(Eo eo, W w, C0591b1 c0591b1) {
    }

    /* JADX WARN: Removed duplicated region for block: B:107:0x01ce  */
    /* JADX WARN: Removed duplicated region for block: B:108:0x01dd  */
    /* JADX WARN: Removed duplicated region for block: B:144:0x027f A[LOOP:0: B:3:0x0010->B:144:0x027f, LOOP_END] */
    /* JADX WARN: Removed duplicated region for block: B:170:0x029d A[EDGE_INSN: B:170:0x029d->B:145:0x029d BREAK  A[LOOP:0: B:3:0x0010->B:144:0x027f], SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public com.google.android.gms.internal.ads.A3 f(com.google.android.gms.internal.ads.B3 r20) throws java.lang.Throwable {
        /*
            Method dump skipped, instructions count: 720
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.C1732Mb.f(com.google.android.gms.internal.ads.B3):com.google.android.gms.internal.ads.A3");
    }

    public U g(Object... objArr) {
        Constructor constructorZza;
        AtomicBoolean atomicBoolean = (AtomicBoolean) this.c;
        synchronized (atomicBoolean) {
            if (!atomicBoolean.get()) {
                try {
                    constructorZza = ((Q) this.b).zza();
                } catch (ClassNotFoundException unused) {
                    ((AtomicBoolean) this.c).set(true);
                } catch (Exception e) {
                    throw new RuntimeException("Error instantiating extension", e);
                }
            }
            constructorZza = null;
        }
        if (constructorZza == null) {
            return null;
        }
        try {
            return (U) constructorZza.newInstance(objArr);
        } catch (Exception e2) {
            throw new IllegalStateException("Unexpected error creating extractor", e2);
        }
    }

    /* JADX WARN: Code restructure failed: missing block: B:102:0x029f, code lost:
    
        return r12;
     */
    /* JADX WARN: Code restructure failed: missing block: B:66:0x01ca, code lost:
    
        r15.disconnect();
     */
    /* JADX WARN: Code restructure failed: missing block: B:97:0x0255, code lost:
    
        com.google.android.gms.ads.internal.util.client.i.h("Received error HTTP response code: " + r0);
     */
    /* JADX WARN: Code restructure failed: missing block: B:98:0x027c, code lost:
    
        throw new com.google.android.gms.internal.ads.zzdwf(1, "Received error HTTP response code: " + r0);
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public com.google.android.gms.internal.ads.Vl j(com.google.android.gms.internal.ads.Ul r22) throws com.google.android.gms.internal.ads.zzdwf {
        /*
            Method dump skipped, instructions count: 700
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.C1732Mb.j(com.google.android.gms.internal.ads.Ul):com.google.android.gms.internal.ads.Vl");
    }

    @Override // com.google.android.gms.internal.ads.Ai
    public void k(boolean z, Context context, C2058fh c2058fh) throws zzdgh {
        zzfcw zzfcwVar;
        try {
            C2369mq c2369mq = (C2369mq) ((C2880ym) this.b).b;
            c2369mq.b(z);
            try {
                c2369mq.a.Q();
            } finally {
            }
        } catch (zzfcw e) {
            com.google.android.gms.ads.internal.util.client.i.i("Cannot show rewarded video.", e);
            throw new zzdgh(e.getCause());
        }
    }

    public void l(com.google.android.gms.ads.query.a aVar) {
        InterfaceC1787Vc interfaceC1787Vc;
        com.google.android.gms.dynamic.b bVar;
        InterfaceC1787Vc interfaceC1787Vc2;
        zzm zzmVarA;
        long jCurrentTimeMillis = System.currentTimeMillis();
        Context context = (Context) this.b;
        synchronized (C1732Mb.class) {
            try {
                if (d == null) {
                    C1608n c1608n = C1614q.f.b;
                    BinderC2739va binderC2739va = new BinderC2739va();
                    c1608n.getClass();
                    d = (InterfaceC1787Vc) new C1590e(context, binderC2739va).d(context, false);
                }
                interfaceC1787Vc = d;
            } catch (Throwable th) {
                throw th;
            }
        }
        if (interfaceC1787Vc == null) {
            aVar.a("Internal Error, query info generator is null.");
            return;
        }
        com.google.android.gms.dynamic.b bVar2 = new com.google.android.gms.dynamic.b(context);
        com.google.android.gms.ads.internal.client.y0 y0Var = (com.google.android.gms.ads.internal.client.y0) this.c;
        if (y0Var == null) {
            bVar = bVar2;
            interfaceC1787Vc2 = interfaceC1787Vc;
            zzmVarA = new zzm(8, -1L, new Bundle(), -1, new ArrayList(), false, -1, false, null, null, null, null, new Bundle(), new Bundle(), new ArrayList(), null, null, false, null, -1, null, new ArrayList(), 60000, null, 0, jCurrentTimeMillis);
        } else {
            bVar = bVar2;
            interfaceC1787Vc2 = interfaceC1787Vc;
            y0Var.n = jCurrentTimeMillis;
            zzmVarA = com.google.android.gms.ads.internal.client.R0.a(context, y0Var);
        }
        try {
            interfaceC1787Vc2.K2(bVar, new zzbyz(null, "BANNER", null, zzmVarA, 0, null), new BinderC1726Lb(aVar));
        } catch (RemoteException unused) {
            aVar.a("Internal Error.");
        }
    }

    @Override // com.google.android.gms.ads.mediation.c
    public void s(com.google.android.gms.ads.b bVar) {
        try {
            String canonicalName = ((com.google.android.gms.ads.mediation.a) this.c).getClass().getCanonicalName();
            int i = bVar.a;
            String str = bVar.b;
            com.google.android.gms.ads.internal.util.client.i.d(canonicalName + "failed to load mediation ad: ErrorCode = " + i + ". ErrorMessage = " + str + ". ErrorDomain = " + bVar.c);
            InterfaceC1671Ca interfaceC1671Ca = (InterfaceC1671Ca) this.b;
            interfaceC1671Ca.S0(bVar.a());
            interfaceC1671Ca.I0(i, str);
            interfaceC1671Ca.e(i);
        } catch (RemoteException e) {
            com.google.android.gms.ads.internal.util.client.i.f("", e);
        }
    }

    @Override // com.google.android.gms.internal.ads.Ai
    /* renamed from: zza, reason: collision with other method in class */
    public Vp mo17zza() {
        return (Vp) this.c;
    }

    public C1732Mb(Context context) {
        this.a = 7;
        this.b = context;
        this.c = null;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2589rw
    /* renamed from: zza */
    public Fw mo22zza() {
        Fw fwMo22zza = ((InterfaceC2589rw) this.c).mo22zza();
        C2143he c2143he = (C2143he) this.b;
        Os os = new Os(c2143he, 12);
        return new C2011ee(c2143he.a, fwMo22zza, c2143he.n, c2143he.o, c2143he, os);
    }

    public /* synthetic */ C1732Mb(C2077g c2077g) {
        this.a = 1;
        this.c = c2077g;
    }

    @Override // com.google.android.gms.internal.ads.K3
    /* renamed from: zza, reason: collision with other method in class */
    public File mo18zza() {
        if (((File) this.c) == null) {
            this.c = new File(((Context) this.b).getCacheDir(), "volley");
        }
        return (File) this.c;
    }

    public C1732Mb(C2125h3 c2125h3) {
        this.a = 5;
        this.c = c2125h3;
        this.b = new C2466p0(4, new byte[4]);
    }

    @Override // com.google.android.gms.internal.ads.Hq
    /* renamed from: zza */
    public void mo13zza() {
        D7 d7 = (D7) ((C2752vn) this.b).d;
        C7 c7 = (C7) this.c;
        Parcel parcelF3 = d7.f3();
        AbstractC2857y5.e(parcelF3, c7);
        d7.d4(1, parcelF3);
    }

    public C1732Mb(com.google.firebase.tracing.a aVar) {
        this.a = 11;
        this.b = aVar;
    }

    public /* synthetic */ C1732Mb(Object obj, boolean z, Object obj2, int i) {
        this.a = i;
        this.b = obj2;
        this.c = obj;
    }

    public C1732Mb(int i) {
        this.a = i;
        switch (i) {
            case 4:
                this.b = new Kn();
                this.c = new C2854y2();
                break;
            case 12:
                break;
            default:
                ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream(com.google.android.gms.ads.g.MAX_CONTENT_URL_LENGTH);
                this.b = byteArrayOutputStream;
                this.c = new DataOutputStream(byteArrayOutputStream);
                break;
        }
    }

    @Override // com.google.android.gms.internal.ads.Pv
    public void zza(Throwable th) {
        String message;
        switch (this.a) {
            case 15:
                C1682Df c1682Df = (C1682Df) this.c;
                C2155hq c2155hq = c1682Df.h;
                List listJ = c1682Df.j();
                c2155hq.a(c1682Df.g.c(c1682Df.e, c1682Df.f, false, (String) this.b, null, listJ), null);
                return;
            case 16:
            case 18:
            case 20:
            case EventType.WINDOW_STATE /* 22 */:
            default:
                com.google.android.datatransport.cct.internal.s sVar = (com.google.android.datatransport.cct.internal.s) this.c;
                synchronized (sVar) {
                    try {
                        C1890bn c1890bn = (C1890bn) sVar.h;
                        Vp vp = (Vp) this.b;
                        c1890bn.b(vp);
                        Vp vpA = ((C1890bn) sVar.h).a();
                        if (vp.v0) {
                            while (vpA != null) {
                                sVar.u(vpA);
                                vpA = ((C1890bn) sVar.h).a();
                            }
                        } else if (vpA != null) {
                            sVar.u(vpA);
                        }
                    } finally {
                    }
                }
                return;
            case 17:
                AbstractC2270kd.f.execute(new RunnableC1989e((C2659tg) this.c, 25));
                ((com.quizlet.remote.model.notes.e) this.b).zza(th);
                return;
            case 19:
                if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.s5)).booleanValue()) {
                    com.google.android.gms.ads.internal.j.C.h.g("omid native display exp", th);
                    return;
                }
                return;
            case 21:
            case EventType.AUDIO /* 23 */:
                return;
            case EventType.VIDEO /* 24 */:
                try {
                    C1798Xb c1798Xb = (C1798Xb) this.c;
                    zze zzeVarA = AbstractC1972di.a(th);
                    if (AbstractC2543qs.i(th.getMessage())) {
                        message = zzeVarA.b;
                    } else {
                        message = th.getMessage();
                    }
                    zzbb zzbbVar = new zzbb(message, zzeVarA.a);
                    Parcel parcelF3 = c1798Xb.f3();
                    AbstractC2857y5.c(parcelF3, zzbbVar);
                    c1798Xb.d4(2, parcelF3);
                    return;
                } catch (RemoteException unused) {
                    com.google.android.gms.ads.internal.util.A.m();
                    return;
                }
        }
    }

    public C1732Mb(Q q) {
        this.a = 2;
        this.b = q;
        this.c = new AtomicBoolean(false);
    }

    public C1732Mb(C1 c1) {
        this.a = 6;
        I3 i3 = new I3(0, (byte) 0);
        this.b = c1;
        this.c = i3;
    }

    @Override // com.google.android.gms.internal.ads.Xh
    /* renamed from: b, reason: collision with other method in class */
    public void mo16b(Object obj) {
        ((InterfaceC1928ci) obj).zzb((String) this.b, (String) this.c);
    }

    public C1732Mb(B7 b7) {
        this.a = 8;
        this.c = b7;
        this.b = new HashMap();
    }

    public C1732Mb(C1765Re c1765Re, Context context, String str) {
        this.a = 14;
        DC dcA = DC.a(context);
        BC bc = c1765Re.E0;
        Mm mm = new Mm(dcA, bc, c1765Re.F0, 5);
        BC bcB = BC.b(new Ok(bc, 23));
        BC bcB2 = BC.b(LA.t);
        BC bcB3 = BC.b(new C2873yf(dcA, c1765Re.c, c1765Re.A, mm, bcB, bcB2));
        this.b = BC.b(new Ck(bcB3, bcB, bcB2, 4));
        this.c = BC.b(new C2233jj(DC.b(str), bcB3, dcA, bcB, bcB2, c1765Re.j, c1765Re.C, c1765Re.x));
    }
}

package com.google.android.gms.internal.ads;

import android.content.Context;
import android.database.sqlite.SQLiteDatabase;
import android.os.RemoteException;
import android.view.View;
import com.comscore.streaming.EventType;
import com.google.android.gms.ads.internal.client.zzt;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.WeakHashMap;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Matcher;

/* loaded from: classes2.dex */
public final class Os implements K, InterfaceC1687Ee, InterfaceC2399nd, com.google.android.gms.ads.mediation.c, Pv, Xh, Ol, InterfaceC2316lg, com.google.android.gms.ads.internal.d, Rn {
    public static Os c;
    public static final C2806wy d = new C2806wy(22);
    public final /* synthetic */ int a;
    public Object b;

    public /* synthetic */ Os(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    public static final Os e(Context context) {
        Os os;
        synchronized (Os.class) {
            try {
                if (c == null) {
                    c = new Os(context);
                }
                os = c;
            } catch (Throwable th) {
                throw th;
            }
        }
        return os;
    }

    private final void j(Throwable th) {
    }

    @Override // com.google.android.gms.ads.internal.d
    public synchronized void a() {
        com.google.android.gms.ads.internal.d dVar = (com.google.android.gms.ads.internal.d) this.b;
        if (dVar != null) {
            dVar.a();
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2399nd
    /* renamed from: b */
    public void mo21b(Object obj) {
        switch (this.a) {
            case 9:
                V9 v9 = (V9) obj;
                com.google.android.gms.ads.internal.util.A.l("Getting a new session for JS Engine.");
                v9.getClass();
                ((C2313ld) ((C1920ca) this.b).b).c(new C2095ga(v9));
                break;
            case 16:
                InterfaceC2102gh interfaceC2102gh = (InterfaceC2102gh) obj;
                String message = ((zzdgh) this.b).getMessage();
                if (message == null) {
                    message = "Internal show error.";
                }
                interfaceC2102gh.r(AbstractC1972di.x(12, message, null));
                break;
            case 17:
                ((Bh) obj).d((zzt) this.b);
                break;
            default:
                ((Uh) obj).r((T6) this.b);
                break;
        }
    }

    @Override // com.google.android.gms.internal.ads.Pv
    /* renamed from: c */
    public void mo15c(Object obj) {
        switch (this.a) {
            case 15:
                ((Kg) this.b).a.a();
                return;
            case 20:
                C1849aq c1849aq = (C1849aq) obj;
                if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.g6)).booleanValue()) {
                    Cl cl = (Cl) this.b;
                    C1889bm c1889bm = cl.e;
                    Xp xp = (Xp) c1849aq.b.b;
                    int i = xp.f;
                    synchronized (c1889bm.g) {
                        c1889bm.b = i;
                    }
                    C1889bm c1889bm2 = cl.e;
                    long j = xp.g;
                    synchronized (c1889bm2.h) {
                        c1889bm2.c = j;
                    }
                    return;
                }
                return;
            default:
                try {
                    ((Gq) this.b).b((SQLiteDatabase) obj);
                    return;
                } catch (Exception e) {
                    com.google.android.gms.ads.internal.util.client.i.e("Error executing function on offline buffered ping database: ".concat(String.valueOf(e.getMessage())));
                    return;
                }
        }
    }

    @Override // com.google.android.gms.internal.ads.Ol
    public com.google.common.util.concurrent.e d(zzbvl zzbvlVar) {
        Jl jl = (Jl) ((C2326lq) this.b).c;
        String str = zzbvlVar.h;
        synchronized (jl.b) {
            try {
                int i = jl.h;
                if (i != 1 && i != 3) {
                    return AbstractC2025es.C(new zzdyq(2));
                }
                if (jl.c) {
                    return jl.a;
                }
                jl.h = 3;
                jl.c = true;
                jl.g = str;
                jl.f.c();
                C2313ld c2313ld = jl.a;
                c2313ld.a.a(new Il(jl, 1), AbstractC2270kd.g);
                return c2313ld;
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    @Override // com.google.android.gms.ads.internal.d
    public synchronized void f(View view) {
        com.google.android.gms.ads.internal.d dVar = (com.google.android.gms.ads.internal.d) this.b;
        if (dVar != null) {
            dVar.f(view);
        }
    }

    public AtomicReference g(String str) {
        synchronized (this) {
            try {
                HashMap map = (HashMap) this.b;
                if (!map.containsKey(str)) {
                    map.put(str, new AtomicReference());
                }
            } catch (Throwable th) {
                throw th;
            }
        }
        return (AtomicReference) ((HashMap) this.b).get(str);
    }

    @Override // com.google.android.gms.internal.ads.K
    public long h(long j) {
        ((Z) this.b).getClass();
        String str = Yo.a;
        return Math.max(0L, Math.min((j * r0.e) / 1000000, r0.j - 1));
    }

    public void i(long j, Kn kn) {
        switch (this.a) {
            case 3:
                LA.i(j, kn, ((B1) this.b).H);
                break;
            default:
                LA.i(j, kn, (InterfaceC2380n0[]) ((C2326lq) this.b).c);
                break;
        }
    }

    public void k(boolean z) {
        synchronized (Os.class) {
            try {
                Ps ps = (Ps) this.b;
                ps.u(Boolean.valueOf(z), "paidv2_publisher_option");
                if (!z) {
                    ps.v("paidv2_creation_time");
                    ps.v("paidv2_id");
                    ps.v("vendor_scoped_gpid_v2_id");
                    ps.v("vendor_scoped_gpid_v2_creation_time");
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    @Override // com.google.android.gms.internal.ads.Rn
    public void o(AbstractC2359mg abstractC2359mg) {
        switch (this.a) {
            case EventType.CDN /* 26 */:
                Jn jn = (Jn) this.b;
                C1778Tf c1778Tf = (C1778Tf) abstractC2359mg;
                synchronized (jn) {
                    C1778Tf c1778Tf2 = jn.i;
                    if (c1778Tf2 != null) {
                        C2403nh c2403nh = c1778Tf2.c;
                        c2403nh.getClass();
                        c2403nh.j1(new C2360mh(null));
                    }
                    jn.i = c1778Tf;
                    c1778Tf.a();
                }
                return;
            default:
                Tp tp = (Tp) this.b;
                C2105gk c2105gk = (C2105gk) abstractC2359mg;
                synchronized (tp) {
                    try {
                        tp.d = c2105gk;
                        if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.G3)).booleanValue()) {
                            c2105gk.s.a = tp.c;
                        }
                        tp.d.a();
                    } catch (Throwable th) {
                        throw th;
                    }
                }
                return;
        }
    }

    @Override // com.google.android.gms.ads.mediation.c
    public void s(com.google.android.gms.ads.b bVar) {
        try {
            ((InterfaceC1809Za) this.b).r(bVar.a());
        } catch (RemoteException e) {
            com.google.android.gms.ads.internal.util.client.i.f("", e);
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2316lg
    public com.google.android.gms.ads.internal.client.v0 zza() throws zzfcw {
        try {
            return ((InterfaceC1965db) ((C2880ym) this.b).b).zze();
        } catch (RemoteException e) {
            throw new zzfcw(e);
        }
    }

    @Override // com.google.android.gms.ads.internal.d
    public synchronized void zzb() {
        com.google.android.gms.ads.internal.d dVar = (com.google.android.gms.ads.internal.d) this.b;
        if (dVar != null) {
            dVar.zzb();
        }
    }

    public Os(int i) {
        this.a = i;
        switch (i) {
            case 6:
                this.b = new HashMap();
                break;
            case 11:
                this.b = new WeakHashMap();
                break;
            case EventType.SUBS /* 25 */:
                break;
            default:
                C2305lB c2305lB = C2305lB.c;
                Lr lr = new Lr(new InterfaceC2001eB[]{C1.l, d}, 5);
                Charset charset = WA.a;
                this.b = lr;
                break;
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1687Ee
    /* renamed from: zza, reason: collision with other method in class */
    public void mo20zza() {
        switch (this.a) {
            case 8:
                com.google.android.gms.ads.internal.j.C.k.getClass();
                long jCurrentTimeMillis = System.currentTimeMillis();
                androidx.work.impl.background.greedy.d dVar = (androidx.work.impl.background.greedy.d) this.b;
                long j = dVar.a;
                Long lValueOf = Long.valueOf(jCurrentTimeMillis - j);
                ArrayList arrayList = (ArrayList) dVar.c;
                arrayList.add(lValueOf);
                com.google.android.gms.ads.internal.util.A.l("LoadNewJavascriptEngine(onEngLoaded) latency is " + String.valueOf(arrayList.get(0)) + " ms.");
                com.google.android.gms.ads.internal.util.F.l.postDelayed(new Y9((C2007ea) dVar.b, (C1964da) dVar.d, (V9) dVar.e, arrayList, j, 0), (long) ((Integer) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.c)).intValue());
                return;
            case EventType.CDN /* 26 */:
                Jn jn = (Jn) this.b;
                synchronized (jn) {
                    jn.i = null;
                }
                return;
            default:
                Tp tp = (Tp) this.b;
                synchronized (tp) {
                    tp.d = null;
                }
                return;
        }
    }

    public Os(Context context) {
        this.a = 0;
        if (Ps.c == null) {
            Ps.c = new Ps(context);
        }
        this.b = Ps.c;
    }

    public Os(J8 j8) {
        Context context;
        this.a = 7;
        this.b = j8;
        try {
            context = (Context) com.google.android.gms.dynamic.b.I3(j8.g());
        } catch (RemoteException | NullPointerException e) {
            com.google.android.gms.ads.internal.util.client.i.f("", e);
            context = null;
        }
        if (context != null) {
            try {
                ((J8) this.b).U(new com.google.android.gms.dynamic.b(new com.google.android.gms.ads.formats.a(context)));
            } catch (RemoteException e2) {
                com.google.android.gms.ads.internal.util.client.i.f("", e2);
            }
        }
    }

    public Os(byte[] bArr) {
        this.a = 5;
        this.b = new byte[256];
        for (int i = 0; i < 256; i++) {
            ((byte[]) this.b)[i] = (byte) i;
        }
        int i2 = 0;
        for (int i3 = 0; i3 < 256; i3++) {
            byte[] bArr2 = (byte[]) this.b;
            byte b = bArr2[i3];
            i2 = (i2 + b + bArr[i3 % bArr.length]) & 255;
            bArr2[i3] = bArr2[i2];
            bArr2[i2] = b;
        }
    }

    @Override // com.google.android.gms.internal.ads.Pv
    public void zza(Throwable th) throws NumberFormatException {
        switch (this.a) {
            case 15:
                return;
            case 20:
                if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.g6)).booleanValue()) {
                    Matcher matcher = Cl.h.matcher(th.getMessage());
                    if (matcher.matches()) {
                        String strGroup = matcher.group(1);
                        C1889bm c1889bm = ((Cl) this.b).e;
                        int i = Integer.parseInt(strGroup);
                        synchronized (c1889bm.g) {
                            c1889bm.b = i;
                        }
                        return;
                    }
                    return;
                }
                return;
            default:
                com.google.android.gms.ads.internal.util.client.i.e("Failed to get offline buffered ping database: ".concat(String.valueOf(th.getMessage())));
                return;
        }
    }
}

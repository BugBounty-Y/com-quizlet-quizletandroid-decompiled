package com.google.android.gms.internal.ads;

import android.content.Context;
import android.os.Binder;
import android.os.Parcel;
import android.os.RemoteException;
import android.text.TextUtils;
import androidx.appcompat.widget.C0110t;
import com.comscore.streaming.EventType;
import dalvik.system.DexClassLoader;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.atomic.AtomicBoolean;

/* renamed from: com.google.android.gms.internal.ads.e, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final /* synthetic */ class RunnableC1989e implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;

    public /* synthetic */ RunnableC1989e(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    private final void a() {
        I3 i3 = (I3) this.b;
        synchronized (i3) {
            try {
                C2472p6 c2472p6 = (C2472p6) i3.d;
                if (c2472p6.b) {
                    B5 b5 = c2472p6.a;
                    byte[] bArr = (byte[]) i3.c;
                    C2900z5 c2900z5 = (C2900z5) b5;
                    Parcel parcelF3 = c2900z5.f3();
                    parcelF3.writeByteArray(bArr);
                    c2900z5.d4(5, parcelF3);
                    C2900z5 c2900z52 = (C2900z5) c2472p6.a;
                    Parcel parcelF32 = c2900z52.f3();
                    parcelF32.writeInt(0);
                    c2900z52.d4(6, parcelF32);
                    B5 b52 = c2472p6.a;
                    int i = i3.b;
                    C2900z5 c2900z53 = (C2900z5) b52;
                    Parcel parcelF33 = c2900z53.f3();
                    parcelF33.writeInt(i);
                    c2900z53.d4(7, parcelF33);
                    C2900z5 c2900z54 = (C2900z5) c2472p6.a;
                    Parcel parcelF34 = c2900z54.f3();
                    parcelF34.writeIntArray(null);
                    c2900z54.d4(4, parcelF34);
                    C2900z5 c2900z55 = (C2900z5) c2472p6.a;
                    c2900z55.d4(3, c2900z55.f3());
                }
            } catch (RemoteException unused) {
                com.google.android.gms.ads.internal.util.client.i.k(3);
            }
        }
    }

    private final void b() throws Throwable {
        LinkedHashMap linkedHashMap;
        com.google.android.datatransport.cct.internal.s sVar = (com.google.android.datatransport.cct.internal.s) this.b;
        while (true) {
            try {
                B7 b7 = (B7) ((ArrayBlockingQueue) sVar.b).take();
                A7 a7A = b7.a();
                if (!TextUtils.isEmpty(a7A.a)) {
                    LinkedHashMap linkedHashMap2 = (LinkedHashMap) sVar.c;
                    synchronized (b7.c) {
                        com.google.android.gms.ads.internal.j.C.h.c();
                        linkedHashMap = b7.b;
                    }
                    sVar.v(sVar.t(linkedHashMap2, linkedHashMap), a7A);
                }
            } catch (InterruptedException e) {
                com.google.android.gms.ads.internal.util.client.i.i("CsiReporter:reporter interrupted", e);
                return;
            }
        }
    }

    private final void c() {
        com.google.android.gms.ads.internal.client.r rVar;
        long jLongValue;
        long jIntValue;
        boolean zBooleanValue;
        com.google.android.gms.ads.internal.client.r rVar2;
        long j;
        long j2;
        long j3;
        long j4;
        C1837ae c1837ae = (C1837ae) this.b;
        String strU = C1837ae.u(c1837ae.e);
        try {
            C2601s7 c2601s7 = AbstractC2773w7.E;
            rVar = com.google.android.gms.ads.internal.client.r.d;
            jLongValue = ((Long) rVar.c.a(c2601s7)).longValue() * 1000;
            jIntValue = ((Integer) rVar.c.a(AbstractC2773w7.t)).intValue();
            zBooleanValue = ((Boolean) rVar.c.a(AbstractC2773w7.T1)).booleanValue();
        } catch (Exception e) {
            com.google.android.gms.ads.internal.util.client.i.h("Failed to preload url " + c1837ae.e + " Exception: " + e.getMessage());
            com.google.android.gms.ads.internal.j.C.h.g("VideoStreamExoPlayerCache.preload", e);
            c1837ae.j();
            c1837ae.m(c1837ae.e, strU, "error", C1837ae.v("error", e));
        }
        synchronized (c1837ae) {
            try {
                com.google.android.gms.ads.internal.j.C.k.getClass();
                if (System.currentTimeMillis() - c1837ae.i > jLongValue) {
                    throw new IOException("Timeout reached. Limit: " + jLongValue + " ms");
                }
                if (c1837ae.f) {
                    throw new IOException("Abort requested before buffering finished. ");
                }
                if (!c1837ae.g) {
                    PD pd = c1837ae.d.g;
                    if (!(pd != null)) {
                        throw new IOException("ExoPlayer was released during preloading.");
                    }
                    long jO1 = pd.o1();
                    if (jO1 > 0) {
                        long jM1 = c1837ae.d.g.m1();
                        if (jM1 != c1837ae.j) {
                            boolean z = jM1 > 0;
                            String str = c1837ae.e;
                            if (zBooleanValue) {
                                C2143he c2143he = c1837ae.d;
                                j4 = (c2143he.s == null || !c2143he.s.o) ? c2143he.k : 0L;
                            } else {
                                j4 = -1;
                            }
                            j = jIntValue;
                            j2 = jO1;
                            long jU = zBooleanValue ? c1837ae.d.u() : -1L;
                            j3 = jM1;
                            rVar2 = rVar;
                            com.google.android.gms.ads.internal.util.client.c.b.post(new RunnableC1764Rd(c1837ae, str, strU, j3, j2, j4, jU, zBooleanValue ? c1837ae.d.p() : -1L, z, C2143he.u.get(), C2143he.v.get()));
                            c1837ae.j = j3;
                        } else {
                            rVar2 = rVar;
                            j = jIntValue;
                            j2 = jO1;
                            j3 = jM1;
                        }
                        if (j3 >= j2) {
                            com.google.android.gms.ads.internal.util.client.c.b.post(new RunnableC1782Ud(c1837ae, c1837ae.e, strU, j2));
                        } else if (c1837ae.d.k >= j && j3 > 0) {
                        }
                    } else {
                        rVar2 = rVar;
                    }
                    com.google.android.gms.ads.internal.util.F.l.postDelayed(new RunnableC1989e(c1837ae, 18), ((Long) rVar2.c.a(AbstractC2773w7.F)).longValue());
                    return;
                }
                com.google.android.gms.ads.internal.j.C.A.a.remove(c1837ae.h);
            } finally {
            }
        }
    }

    private final void d() {
        C1724Kf c1724Kf = ((C1694Ff) this.b).b.d;
        synchronized (c1724Kf) {
            c1724Kf.b();
            c1724Kf.i = true;
        }
    }

    private final void e() {
        Kg kg = (Kg) this.b;
        synchronized (kg) {
            try {
                C1985dw c1985dw = kg.f;
                if (c1985dw.isDone()) {
                    return;
                }
                c1985dw.g(Boolean.TRUE);
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    private final void f() {
        C2058fh c2058fh = (C2058fh) this.b;
        synchronized (c2058fh) {
            com.google.android.gms.ads.internal.util.client.i.e("Timeout waiting for show call succeed to be called.");
            c2058fh.E(new zzdgh("Timeout for show call succeed."));
            c2058fh.e = true;
        }
    }

    @Override // java.lang.Runnable
    public final void run() throws Throwable {
        boolean zBooleanValue;
        String strB;
        Hk hk;
        boolean z = false;
        int i = 1;
        switch (this.a) {
            case 0:
                ((C2077g) this.b).h.getClass();
                return;
            case 1:
                C2593s c2593s = (C2593s) this.b;
                c2593s.k--;
                return;
            case 2:
                L4 l4 = (L4) this.b;
                synchronized (l4.n) {
                    if (l4.o) {
                        return;
                    }
                    l4.o = true;
                    try {
                        L4.j(l4);
                    } catch (Exception e) {
                        ((L4) this.b).f.r(2023, -1L, e);
                    }
                    L4 l42 = (L4) this.b;
                    synchronized (l42.n) {
                        l42.o = false;
                    }
                    return;
                }
            case 3:
                M4 m4 = (M4) this.b;
                if (m4.b != null) {
                    return;
                }
                synchronized (M4.c) {
                    if (m4.b != null) {
                        return;
                    }
                    try {
                        zBooleanValue = ((Boolean) AbstractC2773w7.F2.o()).booleanValue();
                    } catch (IllegalStateException unused) {
                        zBooleanValue = false;
                    }
                    if (zBooleanValue) {
                        try {
                            M4.d = Ds.a(((M4) this.b).a.a, "ADSHIELD");
                            z = zBooleanValue;
                        } catch (Throwable unused2) {
                        }
                    } else {
                        z = zBooleanValue;
                    }
                    ((M4) this.b).b = Boolean.valueOf(z);
                    M4.c.open();
                    return;
                }
            case 4:
                ((ViewOnAttachStateChangeListenerC1952d5) this.b).c();
                return;
            case 5:
                C2556r5 c2556r5 = (C2556r5) this.b;
                try {
                    Z4 z4 = c2556r5.a;
                    DexClassLoader dexClassLoader = z4.c;
                    byte[] bArr = z4.e;
                    String str = c2556r5.b;
                    z4.d.getClass();
                    Class<?> clsLoadClass = dexClassLoader.loadClass(new String(C1.w(str, bArr), "UTF-8"));
                    if (clsLoadClass != null) {
                        byte[] bArr2 = z4.e;
                        String str2 = c2556r5.c;
                        c2556r5.a.d.getClass();
                        c2556r5.d = clsLoadClass.getMethod(new String(C1.w(str2, bArr2), "UTF-8"), c2556r5.e);
                    }
                } catch (zzavs | UnsupportedEncodingException | ClassNotFoundException | NoSuchMethodException | NullPointerException unused3) {
                } catch (Throwable th) {
                    c2556r5.f.countDown();
                    throw th;
                }
                c2556r5.f.countDown();
                return;
            case 6:
                ((F5) this.b).c(3);
                return;
            case 7:
                K5 k5 = (K5) this.b;
                synchronized (k5.c) {
                    if (k5.d && k5.e) {
                        k5.d = false;
                        com.google.android.gms.ads.internal.util.client.i.d("App went background");
                        Iterator it2 = k5.f.iterator();
                        while (it2.hasNext()) {
                            try {
                                ((L5) it2.next()).V(false);
                            } catch (Exception e2) {
                                com.google.android.gms.ads.internal.util.client.i.f("", e2);
                            }
                        }
                    } else {
                        com.google.android.gms.ads.internal.util.client.i.d("App is still foreground");
                    }
                }
                return;
            case 8:
                C2084g6.p((C2084g6) this.b);
                return;
            case 9:
                a();
                return;
            case 10:
                b();
                return;
            case 11:
                F7 f7 = (F7) this.b;
                Context context = f7.c;
                if (f7.f != null || context == null || (strB = androidx.browser.customtabs.l.b(context, null)) == null) {
                    return;
                }
                androidx.browser.customtabs.l.a(context, strB, f7);
                return;
            case 12:
                ((I7) this.b).d();
                return;
            case 13:
                F9 f9 = (F9) this.b;
                if (f9.a == null) {
                    return;
                }
                f9.a.e();
                Binder.flushPendingCommands();
                return;
            case 14:
                ((AtomicBoolean) this.b).getAndSet(true);
                return;
            case 15:
                break;
            case 16:
                ((AbstractC2656td) this.b).y();
                return;
            case 17:
                com.google.android.gms.ads.internal.j.C.A.a.remove((C1746Od) this.b);
                return;
            case 18:
                c();
                return;
            case 19:
                C2743ve c2743ve = ((C1669Be) this.b).a;
                C0110t c0110t = c2743ve.a.c1;
                c0110t.e = true;
                if (c0110t.d) {
                    c0110t.d();
                }
                com.google.android.gms.ads.internal.overlay.d dVarQ = c2743ve.a.Q();
                if (dVarQ != null) {
                    dVarQ.l.removeView(dVarQ.f);
                    dVarQ.j4(true);
                    return;
                }
                return;
            case 20:
                int i2 = C1669Be.H;
                com.google.android.datatransport.cct.internal.s sVarC = com.google.android.gms.ads.internal.j.C.h.c();
                HashSet hashSet = (HashSet) sVarC.g;
                String str3 = (String) this.b;
                if (hashSet.contains(str3)) {
                    return;
                }
                LinkedHashMap linkedHashMap = new LinkedHashMap();
                linkedHashMap.put("sdkVersion", (String) sVarC.f);
                linkedHashMap.put("ue", str3);
                sVarC.v(sVarC.t((LinkedHashMap) sVarC.c, linkedHashMap), null);
                return;
            case 21:
                C2147hi c2147hi = com.google.android.gms.ads.internal.j.C.x;
                Hr hr = ((C2665tm) this.b).a;
                c2147hi.getClass();
                C2147hi.p(new RunnableC2494pm(hr, i));
                return;
            case EventType.WINDOW_STATE /* 22 */:
                ((C1694Ff) this.b).b.d.a();
                return;
            case EventType.AUDIO /* 23 */:
                d();
                return;
            case EventType.VIDEO /* 24 */:
                C1778Tf c1778Tf = (C1778Tf) this.b;
                S8 s8 = c1778Tf.o.d;
                if (s8 == null) {
                    return;
                }
                try {
                    s8.H0((com.google.android.gms.ads.internal.client.K) c1778Tf.q.zzb(), new com.google.android.gms.dynamic.b(c1778Tf.j));
                    return;
                } catch (RemoteException e3) {
                    com.google.android.gms.ads.internal.util.client.i.f("RemoteException when notifyAdLoad is called", e3);
                    return;
                }
            case EventType.SUBS /* 25 */:
                ((C2659tg) this.b).c = false;
                return;
            case EventType.CDN /* 26 */:
                Eg eg = (Eg) this.b;
                AbstractC1795We.F(eg.c);
                eg.h = true;
                return;
            case 27:
                e();
                return;
            case 28:
                f();
                return;
            default:
                ((InterfaceC1886bj) this.b).z();
                return;
        }
        while (true) {
            C2142hd c2142hd = (C2142hd) this.b;
            if (!((AtomicBoolean) c2142hd.g).get()) {
                return;
            }
            AtomicBoolean atomicBoolean = new AtomicBoolean(false);
            com.google.android.gms.ads.internal.util.F.l.post(new RunnableC1989e(atomicBoolean, 14));
            try {
                Thread.sleep(c2142hd.b);
                if (!atomicBoolean.get()) {
                    if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.vd)).booleanValue() && (hk = (Hk) c2142hd.e) != null) {
                        Fi fiA = hk.a();
                        fiA.o("action", "paa");
                        ((Hk) fiA.c).b.execute(new Fk(fiA, 2));
                    }
                }
                do {
                    try {
                        Thread.sleep(c2142hd.c);
                    } catch (InterruptedException unused4) {
                        Thread.currentThread().interrupt();
                    }
                } while (!atomicBoolean.get());
            } catch (InterruptedException unused5) {
                Thread.currentThread().interrupt();
                return;
            }
        }
    }
}

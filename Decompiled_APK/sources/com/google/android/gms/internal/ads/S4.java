package com.google.android.gms.internal.ads;

import android.content.Context;
import android.database.sqlite.SQLiteDatabase;
import android.media.AudioAttributes;
import android.net.ConnectivityManager;
import android.os.Build;
import android.os.Handler;
import android.os.Parcel;
import android.os.RemoteException;
import android.view.View;
import com.comscore.streaming.EventType;
import com.google.android.gms.ads.internal.client.zze;
import com.google.android.gms.common.ConnectionResult;
import com.google.android.gms.common.internal.InterfaceC1653c;
import java.util.Map;
import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicBoolean;

/* loaded from: classes2.dex */
public final class S4 implements InterfaceC1653c, InterfaceC2399nd, com.google.android.gms.ads.mediation.c, Pv, Xh, Ol, Gq, com.google.android.gms.ads.internal.d, Rn, Dp, com.google.android.gms.tasks.c {
    public final /* synthetic */ int a;
    public Object b;

    public S4(Handler handler) {
        this.a = 2;
        this.b = new ExecutorC2769w3(handler, 0);
    }

    private final void e(Throwable th) {
    }

    public static S4 i(Context context) {
        if (context == null) {
            return null;
        }
        ConnectivityManager connectivityManager = (ConnectivityManager) context.getSystemService("connectivity");
        S4 s4 = new S4(0);
        if (connectivityManager != null) {
            try {
                connectivityManager.registerDefaultNetworkCallback(new androidx.work.impl.constraints.d(s4, 3));
                return s4;
            } catch (RuntimeException unused) {
                synchronized (S4.class) {
                    s4.b = null;
                }
            }
        }
        return s4;
    }

    @Override // com.google.android.gms.ads.internal.d
    public void a() {
        C1807Ye c1807Ye = (C1807Ye) this.b;
        ((C2146hh) c1807Ye.H.zzb()).a();
        ((C2490pi) c1807Ye.N.zzb()).a();
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2399nd
    /* renamed from: b, reason: collision with other method in class */
    public void mo21b(Object obj) {
        switch (this.a) {
            case 5:
                com.google.android.gms.ads.internal.util.A.l("Releasing engine reference.");
                ((C1920ca) this.b).e.y();
                break;
            case 12:
                ((InterfaceC1884bh) obj).a0((zze) this.b);
                break;
            case 13:
                ((InterfaceC2703uh) obj).M((AbstractC2359mg) this.b);
                break;
            case 14:
                ((Jh) obj).r0((zzbvl) this.b);
                break;
            case 15:
                ((Uh) obj).z0((T6) this.b);
                break;
            case 16:
                ((InterfaceC2818x9) obj).C0((zzbwj) this.b);
                break;
            default:
                Iq iq = (Iq) this.b;
                ((Mq) obj).A(iq.b);
                break;
        }
    }

    @Override // com.google.android.gms.internal.ads.Pv
    /* renamed from: c */
    public void mo15c(Object obj) {
        switch (this.a) {
            case 11:
                ((C2831xg) this.b).f.S(true);
                return;
            case 18:
                ((InterfaceC2529qe) obj).j("sendMessageToNativeJs", (Map) this.b);
                return;
            default:
                C2670tr c2670tr = (C2670tr) this.b;
                synchronized (c2670tr) {
                    try {
                        c2670tr.j.set(false);
                        if (obj != null) {
                            C2713ur c2713ur = c2670tr.i;
                            c2713ur.e = c2713ur.a;
                            c2713ur.c = 0L;
                            c2670tr.m.set(true);
                            c2670tr.m(obj);
                        }
                        c2670tr.c(obj == null);
                    } catch (Throwable th) {
                        throw th;
                    }
                }
                return;
        }
    }

    @Override // com.google.android.gms.internal.ads.Ol
    public com.google.common.util.concurrent.e d(zzbvl zzbvlVar) {
        Jl jl = (Jl) this.b;
        synchronized (jl.b) {
            try {
                int i = jl.h;
                if (i != 1 && i != 2) {
                    return AbstractC2025es.C(new zzdyq(2));
                }
                if (jl.c) {
                    return jl.a;
                }
                jl.h = 2;
                jl.c = true;
                jl.e = zzbvlVar;
                jl.f.c();
                C2313ld c2313ld = jl.a;
                c2313ld.a.a(new Il(jl, 0), AbstractC2270kd.g);
                return c2313ld;
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    @Override // com.google.android.gms.ads.internal.d
    public void f(View view) {
    }

    @Override // com.google.android.gms.common.internal.InterfaceC1653c
    public void f0(ConnectionResult connectionResult) {
        C2084g6 c2084g6 = (C2084g6) this.b;
        synchronized (c2084g6.c) {
            c2084g6.f = null;
            if (((C2172i6) c2084g6.d) != null) {
                c2084g6.d = null;
            }
            c2084g6.c.notifyAll();
        }
    }

    public void g(B3 b3, androidx.browser.customtabs.k kVar, Qv qv) {
        synchronized (b3.e) {
            b3.i = true;
        }
        b3.d("post-response");
        ((ExecutorC2769w3) this.b).b.post(new C(b3, kVar, qv, 1));
    }

    @Override // com.google.android.gms.internal.ads.Dp
    public Pg h(Cp cp) {
        return ((Qp) this.b).b(cp);
    }

    public void j(long j) {
        C2084g6 c2084g6 = new C2084g6("creation");
        c2084g6.a = Long.valueOf(j);
        c2084g6.c = "nativeObjectNotCreated";
        k(c2084g6);
    }

    public void k(C2084g6 c2084g6) {
        String strC = C2084g6.c(c2084g6);
        com.google.android.gms.ads.internal.util.client.i.g("Dispatching AFMA event on publisher webview: ".concat(strC));
        C2904z9 c2904z9 = (C2904z9) this.b;
        Parcel parcelF3 = c2904z9.f3();
        parcelF3.writeString(strC);
        c2904z9.d4(1, parcelF3);
    }

    @Override // com.google.android.gms.internal.ads.Rn
    public void o(AbstractC2359mg abstractC2359mg) {
        switch (this.a) {
            case EventType.AUDIO /* 23 */:
                C2326lq c2326lq = (C2326lq) this.b;
                synchronized (c2326lq) {
                    c2326lq.d = abstractC2359mg.f;
                    abstractC2359mg.a();
                }
                return;
            default:
                C1766Rf c1766Rf = (C1766Rf) abstractC2359mg;
                BinderC2625sp binderC2625sp = (BinderC2625sp) this.b;
                synchronized (binderC2625sp) {
                    try {
                        C1766Rf c1766Rf2 = binderC2625sp.k;
                        if (c1766Rf2 != null) {
                            c1766Rf2.b();
                        }
                        binderC2625sp.k = c1766Rf;
                        InterfaceC2529qe interfaceC2529qe = c1766Rf.j;
                        if (interfaceC2529qe != null) {
                            interfaceC2529qe.W(binderC2625sp);
                        }
                        binderC2625sp.f.b(new BinderC1772Sf(c1766Rf, binderC2625sp, binderC2625sp.f, binderC2625sp.h));
                        c1766Rf.a();
                    } catch (Throwable th) {
                        throw th;
                    }
                }
                return;
        }
    }

    @Override // com.google.android.gms.ads.mediation.c
    public void s(com.google.android.gms.ads.b bVar) {
        switch (this.a) {
            case 6:
                try {
                    ((InterfaceC1797Xa) this.b).r(bVar.a());
                    break;
                } catch (RemoteException e) {
                    com.google.android.gms.ads.internal.util.client.i.f("", e);
                    return;
                }
            default:
                try {
                    ((InterfaceC1878bb) this.b).r(bVar.a());
                    break;
                } catch (RemoteException e2) {
                    com.google.android.gms.ads.internal.util.client.i.f("", e2);
                }
        }
    }

    @Override // com.google.android.gms.tasks.c
    public void t(Exception exc) {
        if (exc instanceof InterruptedException) {
            Thread.currentThread().interrupt();
        }
        ((androidx.browser.customtabs.k) ((com.quizlet.data.repository.achievements.h) this.b).c).r(2025, -1L, exc);
    }

    @Override // com.google.android.gms.internal.ads.Rn
    public void zza() {
        switch (this.a) {
            case EventType.AUDIO /* 23 */:
                synchronized (((C2326lq) this.b)) {
                }
                return;
            default:
                BinderC2625sp binderC2625sp = (BinderC2625sp) this.b;
                synchronized (binderC2625sp) {
                    binderC2625sp.k = null;
                }
                return;
        }
    }

    @Override // com.google.android.gms.ads.internal.d
    public void zzb() {
        ((Vg) ((C1807Ye) this.b).L.zzb()).onAdClicked();
    }

    public /* synthetic */ S4(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    public S4(int i) {
        this.a = i;
        switch (i) {
            case 8:
                AudioAttributes.Builder usage = new AudioAttributes.Builder().setContentType(0).setFlags(0).setUsage(1);
                int i2 = Build.VERSION.SDK_INT;
                if (i2 >= 29) {
                    usage.setAllowedCapturePolicy(1);
                }
                if (i2 >= 32) {
                    usage.setSpatializationBehavior(0);
                }
                this.b = usage.build();
                break;
            case 9:
                this.b = new AtomicBoolean(false);
                break;
        }
    }

    @Override // com.google.android.gms.internal.ads.Pv
    public void zza(Throwable th) {
        switch (this.a) {
            case 11:
                ((C2831xg) this.b).f.S(false);
                return;
            case 18:
                return;
            default:
                C2670tr c2670tr = (C2670tr) this.b;
                synchronized (c2670tr) {
                    try {
                        c2670tr.j.set(false);
                        if ((th instanceof zzfjt) && ((zzfjt) th).a == 0) {
                            throw null;
                        }
                        c2670tr.c(true);
                    } catch (Throwable th2) {
                        throw th2;
                    }
                }
                return;
        }
    }

    public S4(Context context, Executor executor) {
        this.a = 3;
        RunnableFutureC2161hw runnableFutureC2161hw = new RunnableFutureC2161hw(new Q4(context, 0));
        executor.execute(runnableFutureC2161hw);
        this.b = runnableFutureC2161hw;
    }

    public S4(C1765Re c1765Re, Context context, String str, com.google.android.gms.ads.internal.client.zzr zzrVar) {
        this.a = 10;
        DC dcA = DC.a(context);
        DC dcA2 = DC.a(zzrVar);
        DC dcA3 = DC.a(str);
        BC bc = c1765Re.x;
        BC bcB = BC.b(new Ok(bc, 16));
        BC bcB2 = BC.b(new Ok(c1765Re.E0, 23));
        this.b = BC.b(new com.google.android.gms.ads.nonagon.signalgeneration.n(dcA, dcA2, dcA3, BC.b(new com.google.android.gms.ads.nonagon.signalgeneration.t(dcA, c1765Re.c, c1765Re.A, bcB, bcB2, 18)), bcB, bcB2, c1765Re.j, c1765Re.C, bc));
    }

    @Override // com.google.android.gms.internal.ads.Gq
    public Object b(Object obj) {
        C2107gm.f((SQLiteDatabase) obj, (com.google.android.gms.ads.internal.util.client.k) this.b);
        return null;
    }
}

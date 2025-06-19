package com.google.android.gms.internal.ads;

import android.os.RemoteException;
import com.comscore.streaming.EventType;
import java.util.Collections;

/* renamed from: com.google.android.gms.internal.ads.ch, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final /* synthetic */ class C1927ch implements Xh {
    public final /* synthetic */ int a;

    public /* synthetic */ C1927ch(int i) {
        this.a = i;
    }

    @Override // com.google.android.gms.internal.ads.Xh
    /* renamed from: b */
    public final void mo16b(Object obj) {
        int i;
        int i2;
        switch (this.a) {
            case 0:
                ((InterfaceC1884bh) obj).j();
                return;
            case 1:
                ((InterfaceC2102gh) obj).r(AbstractC1972di.x(11, null, null));
                return;
            case 2:
                ((InterfaceC2189ih) obj).K();
                return;
            case 3:
                ((Xg) obj).a();
                return;
            case 4:
                ((Xg) obj).b();
                return;
            case 5:
                ((Xg) obj).q();
                return;
            case 6:
                ((Xg) obj).f();
                return;
            case 7:
                ((Xg) obj).zze();
                return;
            case 8:
                ((InterfaceC2617sh) obj).s();
                return;
            case 9:
                ((com.google.android.gms.ads.rewarded.a) obj).j();
                return;
            case 10:
                ((InterfaceC2832xh) obj).h();
                return;
            case 11:
                ((com.google.android.gms.ads.internal.overlay.j) obj).I3();
                return;
            case 12:
                ((com.google.android.gms.ads.internal.overlay.j) obj).Y3();
                return;
            case 13:
                ((com.google.android.gms.ads.internal.overlay.j) obj).f3();
                return;
            case 14:
                ((com.google.android.gms.ads.internal.overlay.j) obj).v3();
                return;
            case 15:
                ((com.google.android.gms.ads.internal.overlay.j) obj).L2();
                return;
            case 16:
                ((Dh) obj).c();
                return;
            case 17:
                Jn jn = (Jn) ((Eh) obj);
                synchronized (jn) {
                    try {
                        if (!jn.b.d()) {
                            C2668tp c2668tp = jn.b;
                            Gh gh = c2668tp.h;
                            Rh rh = c2668tp.j;
                            synchronized (rh) {
                                i = rh.a;
                            }
                            gh.k1(i);
                            return;
                        }
                        C1979dq c1979dq = jn.f;
                        com.google.android.gms.ads.internal.client.zzr zzrVarE = c1979dq.b;
                        C1778Tf c1778Tf = jn.i;
                        if (c1778Tf != null && c1979dq.q) {
                            zzrVarE = LA.e(jn.a, Collections.singletonList(c1778Tf.m));
                        }
                        synchronized (jn) {
                            C1979dq c1979dq2 = jn.f;
                            c1979dq2.b = zzrVarE;
                            c1979dq2.q = jn.e.n;
                            c1979dq.p = true;
                            try {
                                jn.e4(c1979dq.a);
                            } catch (RemoteException unused) {
                                com.google.android.gms.ads.internal.util.client.i.h("Failed to refresh the banner ad.");
                            }
                            jn.f.p = false;
                        }
                        return;
                    } catch (Throwable th) {
                        throw th;
                    }
                    throw th;
                }
            case 18:
                Jn jn2 = (Jn) ((Eh) obj);
                synchronized (jn2) {
                    C2668tp c2668tp2 = jn2.b;
                    if (c2668tp2.d()) {
                        c2668tp2.c();
                        return;
                    }
                    Rh rh2 = c2668tp2.j;
                    Gh gh2 = c2668tp2.h;
                    synchronized (rh2) {
                        i2 = rh2.b;
                    }
                    gh2.l1(i2);
                    return;
                }
            case 19:
                ((Nh) obj).a();
                return;
            case 20:
                ((Ph) obj).o();
                return;
            case 21:
                ((Ph) obj).d();
                return;
            case EventType.WINDOW_STATE /* 22 */:
                ((Uh) obj).g();
                return;
            case EventType.AUDIO /* 23 */:
                ((Wh) obj).a();
                return;
            case EventType.VIDEO /* 24 */:
                ((InterfaceC1928ci) obj).zza("MalformedJson");
                return;
            case EventType.SUBS /* 25 */:
                ((InterfaceC1928ci) obj).f();
                return;
            case EventType.CDN /* 26 */:
                ((InterfaceC1928ci) obj).zze();
                return;
            case 27:
                ((InterfaceC2015ei) obj).i();
                return;
            case 28:
                ((InterfaceC2015ei) obj).zzi();
                return;
            default:
                ((InterfaceC2103gi) obj).a();
                return;
        }
    }
}

package com.google.android.gms.internal.ads;

import android.os.SystemClock;
import java.util.Map;

/* renamed from: com.google.android.gms.internal.ads.zk, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2921zk implements Mq {
    public final /* synthetic */ int a = 1;
    public final Object b;
    public final Object c;

    public C2921zk(C2429o6 c2429o6, Map map) {
        this.b = map;
        this.c = c2429o6;
    }

    private final void a(String str) {
    }

    private final void b(String str) {
    }

    @Override // com.google.android.gms.internal.ads.Mq
    public final void A(String str) {
        int i = this.a;
    }

    @Override // com.google.android.gms.internal.ads.Mq
    public final void c(Jq jq, String str) {
        switch (this.a) {
            case 0:
                Map map = (Map) this.b;
                if (map.containsKey(jq)) {
                    ((C2429o6) this.c).b(((C2878yk) map.get(jq)).a);
                    return;
                }
                return;
            default:
                if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.g6)).booleanValue()) {
                    if (Jq.RENDERER == jq) {
                        C1889bm c1889bm = (C1889bm) this.b;
                        com.google.android.gms.ads.internal.j.C.k.getClass();
                        long jElapsedRealtime = SystemClock.elapsedRealtime();
                        synchronized (c1889bm) {
                            synchronized (c1889bm.i) {
                                c1889bm.d = jElapsedRealtime;
                            }
                        }
                        return;
                    }
                    if (Jq.PRELOADED_LOADER == jq || Jq.SERVER_TRANSACTION == jq) {
                        C1889bm c1889bm2 = (C1889bm) this.b;
                        com.google.android.gms.ads.internal.j.C.k.getClass();
                        long jElapsedRealtime2 = SystemClock.elapsedRealtime();
                        synchronized (c1889bm2) {
                            synchronized (c1889bm2.f) {
                                c1889bm2.a = jElapsedRealtime2;
                            }
                        }
                        C1932cm c1932cm = (C1932cm) this.c;
                        ((Fi) c1932cm.c).h(new androidx.compose.foundation.gestures.l1(c1932cm, c1889bm2.b(), 9));
                        return;
                    }
                    return;
                }
                return;
        }
    }

    @Override // com.google.android.gms.internal.ads.Mq
    public final void d(Jq jq, String str, Throwable th) {
        switch (this.a) {
            case 0:
                Map map = (Map) this.b;
                if (map.containsKey(jq)) {
                    ((C2429o6) this.c).b(((C2878yk) map.get(jq)).c);
                    return;
                }
                return;
            default:
                if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.g6)).booleanValue() && Jq.RENDERER == jq) {
                    C1889bm c1889bm = (C1889bm) this.b;
                    if (c1889bm.a() != 0) {
                        com.google.android.gms.ads.internal.j.C.k.getClass();
                        long jElapsedRealtime = SystemClock.elapsedRealtime() - c1889bm.a();
                        synchronized (c1889bm) {
                            synchronized (c1889bm.j) {
                                c1889bm.e = jElapsedRealtime;
                            }
                        }
                        return;
                    }
                    return;
                }
                return;
        }
    }

    @Override // com.google.android.gms.internal.ads.Mq
    public final void r(Jq jq, String str) {
        switch (this.a) {
            case 0:
                Map map = (Map) this.b;
                if (map.containsKey(jq)) {
                    ((C2429o6) this.c).b(((C2878yk) map.get(jq)).b);
                    return;
                }
                return;
            default:
                if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.g6)).booleanValue() && Jq.RENDERER == jq) {
                    C1889bm c1889bm = (C1889bm) this.b;
                    if (c1889bm.a() != 0) {
                        com.google.android.gms.ads.internal.j.C.k.getClass();
                        long jElapsedRealtime = SystemClock.elapsedRealtime() - c1889bm.a();
                        synchronized (c1889bm) {
                            synchronized (c1889bm.j) {
                                c1889bm.e = jElapsedRealtime;
                            }
                        }
                        return;
                    }
                    return;
                }
                return;
        }
    }

    public C2921zk(C1889bm c1889bm, C1932cm c1932cm) {
        this.b = c1889bm;
        this.c = c1932cm;
    }
}

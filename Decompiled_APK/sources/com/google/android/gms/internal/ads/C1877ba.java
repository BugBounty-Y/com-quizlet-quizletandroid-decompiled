package com.google.android.gms.internal.ads;

/* renamed from: com.google.android.gms.internal.ads.ba, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1877ba implements InterfaceC2399nd, InterfaceC2356md {
    public final /* synthetic */ C1964da a;
    public final /* synthetic */ Pq b;
    public final /* synthetic */ C2007ea c;

    public /* synthetic */ C1877ba(C2007ea c2007ea, C1964da c1964da, Pq pq) {
        this.a = c1964da;
        this.b = pq;
        this.c = c2007ea;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2399nd
    /* renamed from: b */
    public /* bridge */ /* synthetic */ void mo21b(Object obj) {
        Uq uq;
        com.google.android.gms.ads.internal.util.A.l("loadNewJavascriptEngine (success): Trying to acquire lock");
        C2007ea c2007ea = this.c;
        synchronized (c2007ea.c) {
            try {
                com.google.android.gms.ads.internal.util.A.l("loadNewJavascriptEngine (success): Lock acquired");
                c2007ea.b = 0;
                C1964da c1964da = (C1964da) c2007ea.g;
                if (c1964da != null && this.a != c1964da) {
                    com.google.android.gms.ads.internal.util.A.l("New JS engine is loaded, marking previous one as destroyable.");
                    ((C1964da) c2007ea.g).w();
                }
                c2007ea.g = this.a;
                if (((Boolean) R7.d.o()).booleanValue() && (uq = (Uq) c2007ea.f) != null) {
                    Pq pq = this.b;
                    pq.h(true);
                    uq.b(pq.l());
                }
            } catch (Throwable th) {
                throw th;
            }
        }
        com.google.android.gms.ads.internal.util.A.l("loadNewJavascriptEngine (success): Lock released");
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2356md, com.google.android.gms.internal.ads.Hq
    /* renamed from: zza */
    public void mo13zza() {
        Uq uq;
        com.google.android.gms.ads.internal.util.A.l("loadNewJavascriptEngine (failure): Trying to acquire lock");
        C2007ea c2007ea = this.c;
        synchronized (c2007ea.c) {
            try {
                com.google.android.gms.ads.internal.util.A.l("loadNewJavascriptEngine (failure): Lock acquired");
                c2007ea.b = 1;
                com.google.android.gms.ads.internal.util.A.l("Failed loading new engine. Marking new engine destroyable.");
                this.a.w();
                if (((Boolean) R7.d.o()).booleanValue() && (uq = (Uq) c2007ea.f) != null) {
                    Pq pq = this.b;
                    pq.A("Failed loading new engine");
                    pq.h(false);
                    uq.b(pq.l());
                }
            } catch (Throwable th) {
                throw th;
            }
        }
        com.google.android.gms.ads.internal.util.A.l("loadNewJavascriptEngine (failure): Lock released");
    }
}

package com.google.android.gms.internal.ads;

import android.content.Context;

/* loaded from: classes2.dex */
public final class Fm implements Ai {
    public final /* synthetic */ int a;
    public final /* synthetic */ C2880ym b;
    public final /* synthetic */ Vp c;

    public /* synthetic */ Fm(C2880ym c2880ym, Vp vp, int i) {
        this.a = i;
        this.b = c2880ym;
        this.c = vp;
    }

    @Override // com.google.android.gms.internal.ads.Ai
    public final void k(boolean z, Context context, C2058fh c2058fh) throws zzdgh {
        zzfcw zzfcwVar;
        switch (this.a) {
            case 0:
                try {
                    C2369mq c2369mq = (C2369mq) this.b.b;
                    c2369mq.b(z);
                    try {
                        c2369mq.a.k2(new com.google.android.gms.dynamic.b(context));
                        return;
                    } finally {
                    }
                } catch (zzfcw e) {
                    throw new zzdgh(e.getCause());
                }
            default:
                try {
                    C2369mq c2369mq2 = (C2369mq) this.b.b;
                    c2369mq2.b(z);
                    try {
                        c2369mq2.a.n3(new com.google.android.gms.dynamic.b(context));
                        return;
                    } finally {
                    }
                } catch (zzfcw e2) {
                    throw new zzdgh(e2.getCause());
                }
        }
    }

    @Override // com.google.android.gms.internal.ads.Ai
    /* renamed from: zza */
    public final Vp mo17zza() {
        switch (this.a) {
        }
        return this.c;
    }
}

package com.google.android.gms.ads.nonagon.signalgeneration;

import android.content.Context;
import com.google.android.gms.internal.ads.AbstractC1981ds;
import com.google.android.gms.internal.ads.AbstractC2270kd;
import com.google.android.gms.internal.ads.BC;
import com.google.android.gms.internal.ads.C1706Hf;
import com.google.android.gms.internal.ads.C1736Mf;
import com.google.android.gms.internal.ads.C1985dw;
import com.google.android.gms.internal.ads.C2195in;
import com.google.android.gms.internal.ads.C2227jd;
import com.google.android.gms.internal.ads.C2361mi;
import com.google.android.gms.internal.ads.C2542qr;
import com.google.android.gms.internal.ads.C2830xf;
import com.google.android.gms.internal.ads.C5;
import com.google.android.gms.internal.ads.CC;
import com.google.android.gms.internal.ads.Ek;
import com.google.android.gms.internal.ads.I7;
import com.google.android.gms.internal.ads.InterfaceC2488pg;
import com.google.android.gms.internal.ads.Kk;
import com.google.android.gms.internal.ads.Nj;
import java.util.concurrent.Executor;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.atomic.AtomicBoolean;

/* loaded from: classes2.dex */
public final class H implements CC {
    public final /* synthetic */ int a;
    public final BC b;
    public final BC c;
    public final BC d;
    public final BC e;

    public /* synthetic */ H(BC bc, BC bc2, BC bc3, BC bc4, int i) {
        this.a = i;
        this.b = bc;
        this.c = bc2;
        this.d = bc3;
        this.e = bc4;
    }

    public com.google.android.datatransport.cct.internal.s a() {
        C2227jd c2227jd = AbstractC2270kd.a;
        AbstractC1981ds.s(c2227jd);
        ScheduledExecutorService scheduledExecutorService = (ScheduledExecutorService) this.b.zzb();
        InterfaceC2488pg interfaceC2488pg = (InterfaceC2488pg) this.c.zzb();
        C2195in c2195in = (C2195in) this.d.zzb();
        C2542qr c2542qr = (C2542qr) this.e.zzb();
        com.google.android.datatransport.cct.internal.s sVar = new com.google.android.datatransport.cct.internal.s();
        sVar.g = new C1985dw();
        sVar.a = new AtomicBoolean();
        sVar.b = c2227jd;
        sVar.c = scheduledExecutorService;
        sVar.d = interfaceC2488pg;
        sVar.e = c2195in;
        sVar.f = c2542qr;
        return sVar;
    }

    public I7 b() {
        return new I7((ScheduledExecutorService) this.b.zzb(), (A) this.c.zzb(), (v) this.d.zzb(), (Kk) this.e.zzb());
    }

    @Override // com.google.android.gms.internal.ads.HC
    public final /* bridge */ /* synthetic */ Object zzb() {
        switch (this.a) {
            case 0:
                return new G((Ek) this.b.zzb(), (F) this.c.zzb(), (String) this.d.zzb(), ((Integer) this.e.zzb()).intValue());
            case 1:
                return b();
            case 2:
                C5 c5 = (C5) this.b.zzb();
                Executor executor = (Executor) this.c.zzb();
                Context context = (Context) this.d.zzb();
                return new C1736Mf(executor, new C1706Hf(context, c5), (com.google.android.gms.common.util.a) this.e.zzb());
            case 3:
                return new Nj((Executor) this.b.zzb(), (C1736Mf) this.c.zzb(), (C2361mi) this.d.zzb(), (C2830xf) this.e.zzb());
            default:
                return a();
        }
    }
}

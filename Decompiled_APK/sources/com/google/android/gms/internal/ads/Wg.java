package com.google.android.gms.internal.ads;

import com.comscore.streaming.EventType;

/* loaded from: classes2.dex */
public final class Wg implements CC {
    public final /* synthetic */ int a;
    public final IC b;

    public /* synthetic */ Wg(IC ic, int i) {
        this.a = i;
        this.b = ic;
    }

    @Override // com.google.android.gms.internal.ads.HC
    public final Object zzb() {
        switch (this.a) {
            case 0:
                return new Vg(this.b.zzb());
            case 1:
                return new C2014eh(this.b.zzb());
            case 2:
                C2146hh c2146hh = new C2146hh(this.b.zzb());
                c2146hh.c = false;
                return c2146hh;
            case 3:
                return new C2403nh(this.b.zzb());
            case 4:
                return new C2489ph(this.b.zzb());
            case 5:
                return new C2574rh(this.b.zzb());
            case 6:
                return new C2660th(this.b.zzb());
            case 7:
                return new C2746vh(this.b.zzb());
            case 8:
                return new C2789wh(this.b.zzb());
            case 9:
                return new C2875yh(this.b.zzb());
            case 10:
                Ch ch = new Ch(this.b.zzb());
                ch.c = false;
                return ch;
            case 11:
                return new Ih(this.b.zzb());
            case 12:
                return new Mh(this.b.zzb());
            case 13:
                return new Oh(this.b.zzb());
            case 14:
                return new Qh(this.b.zzb());
            case 15:
                return new Th(this.b.zzb());
            case 16:
                return new Vh(this.b.zzb());
            case 17:
                return new C1885bi(this.b.zzb());
            case 18:
                return new C2190ii(this.b.zzb());
            case 19:
                return new C2232ji(this.b.zzb());
            case 20:
                return new C2404ni(this.b.zzb());
            case 21:
                return new C2490pi(this.b.zzb());
            case EventType.WINDOW_STATE /* 22 */:
                return new C2575ri(this.b.zzb());
            case EventType.AUDIO /* 23 */:
                return new C2661ti(this.b.zzb());
            case EventType.VIDEO /* 24 */:
                return new C2704ui(this.b.zzb());
            default:
                return new Kq(this.b.zzb());
        }
    }
}

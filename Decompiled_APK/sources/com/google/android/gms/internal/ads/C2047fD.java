package com.google.android.gms.internal.ads;

import com.comscore.streaming.EventType;

/* renamed from: com.google.android.gms.internal.ads.fD, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final /* synthetic */ class C2047fD implements Pk, InterfaceC1844al {
    public final /* synthetic */ int a;

    public /* synthetic */ C2047fD(int i) {
        this.a = i;
    }

    @Override // com.google.android.gms.internal.ads.Pk
    /* renamed from: b */
    public void mo10b(Object obj) {
        switch (this.a) {
            case 0:
                WD wd = (WD) obj;
                int i = C2221jD.i1;
                zzik zzikVar = new zzik(2, new zzkp("Player release timed out."), 1003);
                wd.getClass();
                C2093gF c2093gF = zzikVar.h;
                RD rdJ = c2093gF != null ? wd.j(c2093gF) : wd.g();
                wd.i(rdJ, 10, new C2586rt(rdJ, zzikVar));
                break;
            case 1:
            default:
                break;
            case 2:
                WD wd2 = (WD) obj;
                int i2 = C2221jD.i1;
                wd2.i(wd2.l(), 21, new TD(4));
                break;
            case 3:
                WD wd3 = (WD) obj;
                int i3 = C2221jD.i1;
                wd3.i(wd3.g(), 1, new C2047fD(13));
                break;
            case 4:
                WD wd4 = (WD) obj;
                wd4.i(wd4.l(), 23, new C2047fD(14));
                break;
            case 5:
                break;
            case 6:
                break;
            case 7:
                break;
            case 8:
                break;
            case 9:
                break;
            case 10:
                break;
            case 11:
                break;
            case 12:
                break;
            case 13:
                break;
            case 14:
                break;
            case 15:
                break;
            case 16:
                break;
            case 17:
                break;
            case 18:
                break;
            case 19:
                break;
            case 20:
                break;
            case 21:
                break;
            case EventType.WINDOW_STATE /* 22 */:
                break;
            case EventType.AUDIO /* 23 */:
                break;
            case EventType.VIDEO /* 24 */:
                break;
            case EventType.SUBS /* 25 */:
                break;
            case EventType.CDN /* 26 */:
                break;
            case 27:
                break;
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1844al
    public void c(Object obj, C2049fF c2049fF) {
        switch (this.a) {
            case 1:
                break;
            default:
                break;
        }
    }
}

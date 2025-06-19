package com.google.android.gms.internal.ads;

import com.comscore.streaming.AdvertisementDeliveryType;
import com.google.android.gms.ads.internal.client.InterfaceC1582a;
import com.google.android.gms.ads.internal.client.zze;
import com.onetrust.otpublishers.headless.Public.OTUIDisplayReason.OTUIDisplayReasonCode;

/* renamed from: com.google.android.gms.internal.ads.wk, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2792wk implements Jh, InterfaceC2617sh, InterfaceC1840ah, InterfaceC2189ih, InterfaceC1582a, Uh {
    public final C2429o6 a;
    public boolean b = false;

    public C2792wk(C2429o6 c2429o6, Gp gp) {
        this.a = c2429o6;
        c2429o6.b(2);
        if (gp != null) {
            c2429o6.b(AdvertisementDeliveryType.NATIONAL);
        }
    }

    @Override // com.google.android.gms.internal.ads.Jh
    public final void J0(C1849aq c1849aq) {
        this.a.a(new Hh(c1849aq));
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2189ih
    public final synchronized void K() {
        this.a.b(6);
    }

    @Override // com.google.android.gms.internal.ads.Uh
    public final void S(boolean z) {
        this.a.b(true != z ? 1106 : 1105);
    }

    @Override // com.google.android.gms.internal.ads.Uh
    public final void T0(T6 t6) {
        C2429o6 c2429o6 = this.a;
        synchronized (c2429o6) {
            if (c2429o6.c) {
                try {
                    c2429o6.b.g(t6);
                } catch (NullPointerException e) {
                    com.google.android.gms.ads.internal.j.C.h.h("AdMobClearcutLogger.modify", e);
                }
            }
        }
        c2429o6.b(AdvertisementDeliveryType.LOCAL);
    }

    @Override // com.google.android.gms.internal.ads.Uh
    public final void g() {
        this.a.b(1109);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1840ah
    public final void m0(zze zzeVar) {
        int i = zzeVar.a;
        C2429o6 c2429o6 = this.a;
        switch (i) {
            case 1:
                c2429o6.b(101);
                break;
            case 2:
                c2429o6.b(102);
                break;
            case 3:
                c2429o6.b(5);
                break;
            case 4:
                c2429o6.b(103);
                break;
            case 5:
                c2429o6.b(104);
                break;
            case 6:
                c2429o6.b(OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_CONSENT_EXPIRED);
                break;
            case 7:
                c2429o6.b(OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_SERVICE_SPECIFIC_OFF);
                break;
            default:
                c2429o6.b(4);
                break;
        }
    }

    @Override // com.google.android.gms.internal.ads.Uh
    public final void o(boolean z) {
        this.a.b(true != z ? 1108 : 1107);
    }

    @Override // com.google.android.gms.ads.internal.client.InterfaceC1582a
    public final synchronized void onAdClicked() {
        if (this.b) {
            this.a.b(8);
        } else {
            this.a.b(7);
            this.b = true;
        }
    }

    @Override // com.google.android.gms.internal.ads.Uh
    public final void r(T6 t6) {
        C2429o6 c2429o6 = this.a;
        synchronized (c2429o6) {
            if (c2429o6.c) {
                try {
                    c2429o6.b.g(t6);
                } catch (NullPointerException e) {
                    com.google.android.gms.ads.internal.j.C.h.h("AdMobClearcutLogger.modify", e);
                }
            }
        }
        c2429o6.b(1104);
    }

    @Override // com.google.android.gms.internal.ads.Jh
    public final void r0(zzbvl zzbvlVar) {
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2617sh
    public final void s() {
        this.a.b(3);
    }

    @Override // com.google.android.gms.internal.ads.Uh
    public final void z0(T6 t6) {
        C2429o6 c2429o6 = this.a;
        synchronized (c2429o6) {
            if (c2429o6.c) {
                try {
                    c2429o6.b.g(t6);
                } catch (NullPointerException e) {
                    com.google.android.gms.ads.internal.j.C.h.h("AdMobClearcutLogger.modify", e);
                }
            }
        }
        c2429o6.b(AdvertisementDeliveryType.SYNDICATION);
    }
}

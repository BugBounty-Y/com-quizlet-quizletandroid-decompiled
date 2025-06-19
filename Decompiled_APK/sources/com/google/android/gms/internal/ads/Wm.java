package com.google.android.gms.internal.ads;

import android.os.Parcel;
import com.google.android.gms.ads.internal.client.zze;

/* loaded from: classes2.dex */
public final class Wm extends AbstractBinderC2814x5 implements InterfaceC1797Xa {
    public final C2880ym a;

    public Wm(C2880ym c2880ym) {
        super("com.google.android.gms.ads.internal.mediation.client.rtb.IInterstitialCallback");
        this.a = c2880ym;
    }

    @Override // com.google.android.gms.internal.ads.AbstractBinderC2814x5
    public final boolean d4(int i, Parcel parcel, Parcel parcel2) {
        C2880ym c2880ym = this.a;
        if (i == 2) {
            ((Rm) c2880ym.c).v();
        } else if (i == 3) {
            String string = parcel.readString();
            AbstractC2857y5.b(parcel);
            ((Rm) c2880ym.c).I0(0, string);
        } else {
            if (i != 4) {
                return false;
            }
            zze zzeVar = (zze) AbstractC2857y5.a(parcel, zze.CREATOR);
            AbstractC2857y5.b(parcel);
            r(zzeVar);
        }
        parcel2.writeNoException();
        return true;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1797Xa
    public final void r(zze zzeVar) {
        ((Rm) this.a.c).S0(zzeVar);
    }
}

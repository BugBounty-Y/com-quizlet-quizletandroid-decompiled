package com.google.android.gms.internal.ads;

import android.os.IBinder;
import android.os.IInterface;
import android.os.Parcel;
import android.view.View;
import com.google.android.gms.ads.internal.client.zze;

/* loaded from: classes2.dex */
public final class Nm extends AbstractBinderC2814x5 implements InterfaceC1779Ua {
    public final C2880ym a;
    public final /* synthetic */ Om b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public Nm(Om om, C2880ym c2880ym) {
        super("com.google.android.gms.ads.internal.mediation.client.rtb.IBannerCallback");
        this.b = om;
        this.a = c2880ym;
    }

    @Override // com.google.android.gms.internal.ads.AbstractBinderC2814x5
    public final boolean d4(int i, Parcel parcel, Parcel parcel2) {
        C1677Da c1677Da;
        Om om = this.b;
        C2880ym c2880ym = this.a;
        if (i == 1) {
            com.google.android.gms.dynamic.a aVarV3 = com.google.android.gms.dynamic.b.v3(parcel.readStrongBinder());
            AbstractC2857y5.b(parcel);
            om.d = (View) com.google.android.gms.dynamic.b.I3(aVarV3);
            ((Rm) c2880ym.c).v();
        } else if (i == 2) {
            String string = parcel.readString();
            AbstractC2857y5.b(parcel);
            ((Rm) c2880ym.c).I0(0, string);
        } else if (i == 3) {
            zze zzeVar = (zze) AbstractC2857y5.a(parcel, zze.CREATOR);
            AbstractC2857y5.b(parcel);
            r(zzeVar);
        } else {
            if (i != 4) {
                return false;
            }
            IBinder strongBinder = parcel.readStrongBinder();
            if (strongBinder == null) {
                c1677Da = null;
            } else {
                IInterface iInterfaceQueryLocalInterface = strongBinder.queryLocalInterface("com.google.android.gms.ads.internal.mediation.client.IMediationInterscrollerAd");
                c1677Da = iInterfaceQueryLocalInterface instanceof C1677Da ? (C1677Da) iInterfaceQueryLocalInterface : new C1677Da(strongBinder);
            }
            AbstractC2857y5.b(parcel);
            om.e = c1677Da;
            ((Rm) c2880ym.c).v();
        }
        parcel2.writeNoException();
        return true;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1779Ua
    public final void r(zze zzeVar) {
        ((Rm) this.a.c).S0(zzeVar);
    }
}

package com.google.android.gms.internal.ads;

import android.os.IBinder;
import android.os.IInterface;
import android.os.Parcel;
import com.google.android.gms.ads.internal.client.zze;

/* renamed from: com.google.android.gms.internal.ads.an, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class BinderC1846an extends AbstractBinderC2814x5 implements InterfaceC1809Za {
    public final C2880ym a;
    public final /* synthetic */ Om b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public BinderC1846an(Om om, C2880ym c2880ym) {
        super("com.google.android.gms.ads.internal.mediation.client.rtb.INativeCallback");
        this.b = om;
        this.a = c2880ym;
    }

    @Override // com.google.android.gms.internal.ads.AbstractBinderC2814x5
    public final boolean d4(int i, Parcel parcel, Parcel parcel2) {
        InterfaceC1707Ia c1695Ga;
        C2880ym c2880ym = this.a;
        if (i == 1) {
            IBinder strongBinder = parcel.readStrongBinder();
            if (strongBinder == null) {
                c1695Ga = null;
            } else {
                IInterface iInterfaceQueryLocalInterface = strongBinder.queryLocalInterface("com.google.android.gms.ads.internal.mediation.client.IUnifiedNativeAdMapper");
                c1695Ga = iInterfaceQueryLocalInterface instanceof InterfaceC1707Ia ? (InterfaceC1707Ia) iInterfaceQueryLocalInterface : new C1695Ga(strongBinder);
            }
            AbstractC2857y5.b(parcel);
            this.b.d = c1695Ga;
            ((Rm) c2880ym.c).v();
        } else if (i == 2) {
            String string = parcel.readString();
            AbstractC2857y5.b(parcel);
            ((Rm) c2880ym.c).I0(0, string);
        } else {
            if (i != 3) {
                return false;
            }
            zze zzeVar = (zze) AbstractC2857y5.a(parcel, zze.CREATOR);
            AbstractC2857y5.b(parcel);
            r(zzeVar);
        }
        parcel2.writeNoException();
        return true;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1809Za
    public final void r(zze zzeVar) {
        ((Rm) this.a.c).S0(zzeVar);
    }
}

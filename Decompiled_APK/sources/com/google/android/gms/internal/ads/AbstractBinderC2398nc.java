package com.google.android.gms.internal.ads;

import android.os.Bundle;
import android.os.IBinder;
import android.os.IInterface;
import android.os.Parcel;
import com.google.android.gms.ads.internal.client.C1605l0;
import com.google.android.gms.ads.internal.client.InterfaceC1609n0;
import com.google.android.gms.ads.internal.client.zzm;

/* renamed from: com.google.android.gms.internal.ads.nc, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractBinderC2398nc extends AbstractBinderC2814x5 implements InterfaceC2441oc {
    public static final /* synthetic */ int a = 0;

    public AbstractBinderC2398nc() {
        super("com.google.android.gms.ads.internal.rewarded.client.IRewardedAd");
    }

    @Override // com.google.android.gms.internal.ads.AbstractBinderC2814x5
    public final boolean d4(int i, Parcel parcel, Parcel parcel2) {
        InterfaceC2741vc c2655tc = null;
        InterfaceC2741vc c2655tc2 = null;
        C1605l0 c1605l0 = null;
        C2784wc c2784wc = null;
        InterfaceC2569rc c2484pc = null;
        switch (i) {
            case 1:
                zzm zzmVar = (zzm) AbstractC2857y5.a(parcel, zzm.CREATOR);
                IBinder strongBinder = parcel.readStrongBinder();
                if (strongBinder != null) {
                    IInterface iInterfaceQueryLocalInterface = strongBinder.queryLocalInterface("com.google.android.gms.ads.internal.rewarded.client.IRewardedAdLoadCallback");
                    c2655tc = iInterfaceQueryLocalInterface instanceof InterfaceC2741vc ? (InterfaceC2741vc) iInterfaceQueryLocalInterface : new C2655tc(strongBinder);
                }
                AbstractC2857y5.b(parcel);
                Z2(zzmVar, c2655tc);
                parcel2.writeNoException();
                return true;
            case 2:
                IBinder strongBinder2 = parcel.readStrongBinder();
                if (strongBinder2 != null) {
                    IInterface iInterfaceQueryLocalInterface2 = strongBinder2.queryLocalInterface("com.google.android.gms.ads.internal.rewarded.client.IRewardedAdCallback");
                    c2484pc = iInterfaceQueryLocalInterface2 instanceof InterfaceC2569rc ? (InterfaceC2569rc) iInterfaceQueryLocalInterface2 : new C2484pc(strongBinder2, "com.google.android.gms.ads.internal.rewarded.client.IRewardedAdCallback", 0);
                }
                AbstractC2857y5.b(parcel);
                R0(c2484pc);
                parcel2.writeNoException();
                return true;
            case 3:
                boolean zO = o();
                parcel2.writeNoException();
                ClassLoader classLoader = AbstractC2857y5.a;
                parcel2.writeInt(zO ? 1 : 0);
                return true;
            case 4:
                String strF = f();
                parcel2.writeNoException();
                parcel2.writeString(strF);
                return true;
            case 5:
                com.google.android.gms.dynamic.a aVarV3 = com.google.android.gms.dynamic.b.v3(parcel.readStrongBinder());
                AbstractC2857y5.b(parcel);
                D(aVarV3);
                parcel2.writeNoException();
                return true;
            case 6:
                IBinder strongBinder3 = parcel.readStrongBinder();
                if (strongBinder3 != null) {
                    IInterface iInterfaceQueryLocalInterface3 = strongBinder3.queryLocalInterface("com.google.android.gms.ads.internal.rewarded.client.IRewardedAdSkuListener");
                    c2784wc = iInterfaceQueryLocalInterface3 instanceof C2784wc ? (C2784wc) iInterfaceQueryLocalInterface3 : new C2784wc(strongBinder3, "com.google.android.gms.ads.internal.rewarded.client.IRewardedAdSkuListener", 0);
                }
                AbstractC2857y5.b(parcel);
                p0(c2784wc);
                parcel2.writeNoException();
                return true;
            case 7:
                zzbxe zzbxeVar = (zzbxe) AbstractC2857y5.a(parcel, zzbxe.CREATOR);
                AbstractC2857y5.b(parcel);
                Q0(zzbxeVar);
                parcel2.writeNoException();
                return true;
            case 8:
                IBinder strongBinder4 = parcel.readStrongBinder();
                if (strongBinder4 != null) {
                    IInterface iInterfaceQueryLocalInterface4 = strongBinder4.queryLocalInterface("com.google.android.gms.ads.internal.client.IOnAdMetadataChangedListener");
                    c1605l0 = iInterfaceQueryLocalInterface4 instanceof C1605l0 ? (C1605l0) iInterfaceQueryLocalInterface4 : new C1605l0(strongBinder4, "com.google.android.gms.ads.internal.client.IOnAdMetadataChangedListener", 0);
                }
                AbstractC2857y5.b(parcel);
                x1(c1605l0);
                parcel2.writeNoException();
                return true;
            case 9:
                Bundle bundleZzb = zzb();
                parcel2.writeNoException();
                AbstractC2857y5.d(parcel2, bundleZzb);
                return true;
            case 10:
                com.google.android.gms.dynamic.a aVarV32 = com.google.android.gms.dynamic.b.v3(parcel.readStrongBinder());
                ClassLoader classLoader2 = AbstractC2857y5.a;
                boolean z = parcel.readInt() != 0;
                AbstractC2857y5.b(parcel);
                c2(aVarV32, z);
                parcel2.writeNoException();
                return true;
            case 11:
                InterfaceC2312lc interfaceC2312lcJ = j();
                parcel2.writeNoException();
                AbstractC2857y5.e(parcel2, interfaceC2312lcJ);
                return true;
            case 12:
                com.google.android.gms.ads.internal.client.s0 s0VarA = a();
                parcel2.writeNoException();
                AbstractC2857y5.e(parcel2, s0VarA);
                return true;
            case 13:
                InterfaceC1609n0 interfaceC1609n0E4 = com.google.android.gms.ads.internal.client.N0.e4(parcel.readStrongBinder());
                AbstractC2857y5.b(parcel);
                w2(interfaceC1609n0E4);
                parcel2.writeNoException();
                return true;
            case 14:
                zzm zzmVar2 = (zzm) AbstractC2857y5.a(parcel, zzm.CREATOR);
                IBinder strongBinder5 = parcel.readStrongBinder();
                if (strongBinder5 != null) {
                    IInterface iInterfaceQueryLocalInterface5 = strongBinder5.queryLocalInterface("com.google.android.gms.ads.internal.rewarded.client.IRewardedAdLoadCallback");
                    c2655tc2 = iInterfaceQueryLocalInterface5 instanceof InterfaceC2741vc ? (InterfaceC2741vc) iInterfaceQueryLocalInterface5 : new C2655tc(strongBinder5);
                }
                AbstractC2857y5.b(parcel);
                C2(zzmVar2, c2655tc2);
                parcel2.writeNoException();
                return true;
            case 15:
                boolean zF = AbstractC2857y5.f(parcel);
                AbstractC2857y5.b(parcel);
                A2(zF);
                parcel2.writeNoException();
                return true;
            case 16:
                String strZze = zze();
                parcel2.writeNoException();
                parcel2.writeString(strZze);
                return true;
            default:
                return false;
        }
    }
}

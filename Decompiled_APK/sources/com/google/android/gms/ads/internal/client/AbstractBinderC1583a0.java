package com.google.android.gms.ads.internal.client;

import android.os.IBinder;
import android.os.IInterface;
import android.os.Parcel;
import com.google.android.gms.internal.ads.AbstractBinderC2814x5;
import com.google.android.gms.internal.ads.AbstractC2857y5;
import com.google.android.gms.internal.ads.BinderC2739va;
import com.google.android.gms.internal.ads.I9;
import com.google.android.gms.internal.ads.InterfaceC2825xa;
import com.google.android.gms.internal.ads.K9;
import java.util.List;

/* renamed from: com.google.android.gms.ads.internal.client.a0, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractBinderC1583a0 extends AbstractBinderC2814x5 implements InterfaceC1585b0 {
    public AbstractBinderC1583a0() {
        super("com.google.android.gms.ads.internal.client.IMobileAdsSettingManager");
    }

    @Override // com.google.android.gms.internal.ads.AbstractBinderC2814x5
    public final boolean d4(int i, Parcel parcel, Parcel parcel2) {
        K9 i9 = null;
        InterfaceC1603k0 c1599i0 = null;
        switch (i) {
            case 1:
                t();
                parcel2.writeNoException();
                return true;
            case 2:
                float f = parcel.readFloat();
                AbstractC2857y5.b(parcel);
                i2(f);
                parcel2.writeNoException();
                return true;
            case 3:
                String string = parcel.readString();
                AbstractC2857y5.b(parcel);
                c0(string);
                parcel2.writeNoException();
                return true;
            case 4:
                boolean zF = AbstractC2857y5.f(parcel);
                AbstractC2857y5.b(parcel);
                b4(zF);
                parcel2.writeNoException();
                return true;
            case 5:
                com.google.android.gms.dynamic.a aVarV3 = com.google.android.gms.dynamic.b.v3(parcel.readStrongBinder());
                String string2 = parcel.readString();
                AbstractC2857y5.b(parcel);
                z2(aVarV3, string2);
                parcel2.writeNoException();
                return true;
            case 6:
                String string3 = parcel.readString();
                com.google.android.gms.dynamic.a aVarV32 = com.google.android.gms.dynamic.b.v3(parcel.readStrongBinder());
                AbstractC2857y5.b(parcel);
                q3(aVarV32, string3);
                parcel2.writeNoException();
                return true;
            case 7:
                float fZze = zze();
                parcel2.writeNoException();
                parcel2.writeFloat(fZze);
                return true;
            case 8:
                boolean zD = d();
                parcel2.writeNoException();
                ClassLoader classLoader = AbstractC2857y5.a;
                parcel2.writeInt(zD ? 1 : 0);
                return true;
            case 9:
                String strF = f();
                parcel2.writeNoException();
                parcel2.writeString(strF);
                return true;
            case 10:
                String string4 = parcel.readString();
                AbstractC2857y5.b(parcel);
                q2(string4);
                parcel2.writeNoException();
                return true;
            case 11:
                InterfaceC2825xa interfaceC2825xaE4 = BinderC2739va.e4(parcel.readStrongBinder());
                AbstractC2857y5.b(parcel);
                F1(interfaceC2825xaE4);
                parcel2.writeNoException();
                return true;
            case 12:
                IBinder strongBinder = parcel.readStrongBinder();
                if (strongBinder != null) {
                    IInterface iInterfaceQueryLocalInterface = strongBinder.queryLocalInterface("com.google.android.gms.ads.internal.initialization.IInitializationCallback");
                    i9 = iInterfaceQueryLocalInterface instanceof K9 ? (K9) iInterfaceQueryLocalInterface : new I9(strongBinder, "com.google.android.gms.ads.internal.initialization.IInitializationCallback", 0);
                }
                AbstractC2857y5.b(parcel);
                N3(i9);
                parcel2.writeNoException();
                return true;
            case 13:
                List listH = h();
                parcel2.writeNoException();
                parcel2.writeTypedList(listH);
                return true;
            case 14:
                zzfr zzfrVar = (zzfr) AbstractC2857y5.a(parcel, zzfr.CREATOR);
                AbstractC2857y5.b(parcel);
                r0(zzfrVar);
                parcel2.writeNoException();
                return true;
            case 15:
                zzi();
                parcel2.writeNoException();
                return true;
            case 16:
                IBinder strongBinder2 = parcel.readStrongBinder();
                if (strongBinder2 != null) {
                    IInterface iInterfaceQueryLocalInterface2 = strongBinder2.queryLocalInterface("com.google.android.gms.ads.internal.client.IOnAdInspectorClosedListener");
                    c1599i0 = iInterfaceQueryLocalInterface2 instanceof InterfaceC1603k0 ? (InterfaceC1603k0) iInterfaceQueryLocalInterface2 : new C1599i0(strongBinder2, "com.google.android.gms.ads.internal.client.IOnAdInspectorClosedListener", 0);
                }
                AbstractC2857y5.b(parcel);
                v0(c1599i0);
                parcel2.writeNoException();
                return true;
            case 17:
                boolean zF2 = AbstractC2857y5.f(parcel);
                AbstractC2857y5.b(parcel);
                E(zF2);
                parcel2.writeNoException();
                return true;
            case 18:
                String string5 = parcel.readString();
                AbstractC2857y5.b(parcel);
                M(string5);
                parcel2.writeNoException();
                return true;
            default:
                return false;
        }
    }
}

package com.google.android.gms.internal.ads;

import android.os.IBinder;
import android.os.IInterface;
import android.os.Parcel;

/* loaded from: classes2.dex */
public abstract class B8 extends AbstractBinderC2814x5 implements C8 {
    public static final /* synthetic */ int a = 0;

    public B8() {
        super("com.google.android.gms.ads.internal.formats.client.INativeAdViewDelegate");
    }

    @Override // com.google.android.gms.internal.ads.AbstractBinderC2814x5
    public final boolean d4(int i, Parcel parcel, Parcel parcel2) {
        InterfaceC2774w8 c2731v8;
        switch (i) {
            case 1:
                String string = parcel.readString();
                com.google.android.gms.dynamic.a aVarV3 = com.google.android.gms.dynamic.b.v3(parcel.readStrongBinder());
                AbstractC2857y5.b(parcel);
                y2(aVarV3, string);
                parcel2.writeNoException();
                return true;
            case 2:
                String string2 = parcel.readString();
                AbstractC2857y5.b(parcel);
                com.google.android.gms.dynamic.a aVarC = C(string2);
                parcel2.writeNoException();
                AbstractC2857y5.e(parcel2, aVarC);
                return true;
            case 3:
                com.google.android.gms.dynamic.a aVarV32 = com.google.android.gms.dynamic.b.v3(parcel.readStrongBinder());
                AbstractC2857y5.b(parcel);
                D2(aVarV32);
                parcel2.writeNoException();
                return true;
            case 4:
                q();
                parcel2.writeNoException();
                return true;
            case 5:
                com.google.android.gms.dynamic.b.v3(parcel.readStrongBinder());
                parcel.readInt();
                AbstractC2857y5.b(parcel);
                parcel2.writeNoException();
                return true;
            case 6:
                com.google.android.gms.dynamic.a aVarV33 = com.google.android.gms.dynamic.b.v3(parcel.readStrongBinder());
                AbstractC2857y5.b(parcel);
                K0(aVarV33);
                parcel2.writeNoException();
                return true;
            case 7:
                com.google.android.gms.dynamic.a aVarV34 = com.google.android.gms.dynamic.b.v3(parcel.readStrongBinder());
                AbstractC2857y5.b(parcel);
                Y2(aVarV34);
                parcel2.writeNoException();
                return true;
            case 8:
                IBinder strongBinder = parcel.readStrongBinder();
                if (strongBinder == null) {
                    c2731v8 = null;
                } else {
                    IInterface iInterfaceQueryLocalInterface = strongBinder.queryLocalInterface("com.google.android.gms.ads.internal.formats.client.IMediaContent");
                    c2731v8 = iInterfaceQueryLocalInterface instanceof InterfaceC2774w8 ? (InterfaceC2774w8) iInterfaceQueryLocalInterface : new C2731v8(strongBinder);
                }
                AbstractC2857y5.b(parcel);
                q1(c2731v8);
                parcel2.writeNoException();
                return true;
            case 9:
                com.google.android.gms.dynamic.a aVarV35 = com.google.android.gms.dynamic.b.v3(parcel.readStrongBinder());
                AbstractC2857y5.b(parcel);
                m2(aVarV35);
                parcel2.writeNoException();
                return true;
            default:
                return false;
        }
    }
}

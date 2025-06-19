package com.google.android.gms.internal.ads;

import android.content.Intent;
import android.os.Bundle;
import android.os.Parcel;

/* renamed from: com.google.android.gms.internal.ads.Bb, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractBinderC1666Bb extends AbstractBinderC2814x5 implements InterfaceC1672Cb {
    public static final /* synthetic */ int a = 0;

    public AbstractBinderC1666Bb() {
        super("com.google.android.gms.ads.internal.overlay.client.IAdOverlay");
    }

    @Override // com.google.android.gms.internal.ads.AbstractBinderC2814x5
    public final boolean d4(int i, Parcel parcel, Parcel parcel2) {
        switch (i) {
            case 1:
                Bundle bundle = (Bundle) AbstractC2857y5.a(parcel, Bundle.CREATOR);
                AbstractC2857y5.b(parcel);
                p2(bundle);
                parcel2.writeNoException();
                return true;
            case 2:
                parcel2.writeNoException();
                return true;
            case 3:
                s();
                parcel2.writeNoException();
                return true;
            case 4:
                w();
                parcel2.writeNoException();
                return true;
            case 5:
                v();
                parcel2.writeNoException();
                return true;
            case 6:
                Bundle bundle2 = (Bundle) AbstractC2857y5.a(parcel, Bundle.CREATOR);
                AbstractC2857y5.b(parcel);
                B2(bundle2);
                parcel2.writeNoException();
                AbstractC2857y5.d(parcel2, bundle2);
                return true;
            case 7:
                c();
                parcel2.writeNoException();
                return true;
            case 8:
                l();
                parcel2.writeNoException();
                return true;
            case 9:
                y();
                parcel2.writeNoException();
                return true;
            case 10:
                zzi();
                parcel2.writeNoException();
                return true;
            case 11:
                boolean zS3 = s3();
                parcel2.writeNoException();
                ClassLoader classLoader = AbstractC2857y5.a;
                parcel2.writeInt(zS3 ? 1 : 0);
                return true;
            case 12:
                int i2 = parcel.readInt();
                int i3 = parcel.readInt();
                Intent intent = (Intent) AbstractC2857y5.a(parcel, Intent.CREATOR);
                AbstractC2857y5.b(parcel);
                m1(i2, i3, intent);
                parcel2.writeNoException();
                return true;
            case 13:
                com.google.android.gms.dynamic.a aVarV3 = com.google.android.gms.dynamic.b.v3(parcel.readStrongBinder());
                AbstractC2857y5.b(parcel);
                v2(aVarV3);
                parcel2.writeNoException();
                return true;
            case 14:
                d();
                parcel2.writeNoException();
                return true;
            case 15:
                int i4 = parcel.readInt();
                String[] strArrCreateStringArray = parcel.createStringArray();
                int[] iArrCreateIntArray = parcel.createIntArray();
                AbstractC2857y5.b(parcel);
                H1(i4, strArrCreateStringArray, iArrCreateIntArray);
                parcel2.writeNoException();
                return true;
            default:
                return false;
        }
    }
}

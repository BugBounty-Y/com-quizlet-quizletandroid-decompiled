package com.google.android.gms.ads.internal.client;

import android.os.Parcel;
import com.google.android.gms.internal.ads.AbstractBinderC2814x5;
import com.google.android.gms.internal.ads.AbstractC2857y5;

/* loaded from: classes2.dex */
public abstract class C extends AbstractBinderC2814x5 implements D {
    public C() {
        super("com.google.android.gms.ads.internal.client.IAdLoader");
    }

    @Override // com.google.android.gms.internal.ads.AbstractBinderC2814x5
    public final boolean d4(int i, Parcel parcel, Parcel parcel2) {
        if (i == 1) {
            zzm zzmVar = (zzm) AbstractC2857y5.a(parcel, zzm.CREATOR);
            AbstractC2857y5.b(parcel);
            D0(zzmVar);
            parcel2.writeNoException();
            return true;
        }
        if (i == 2) {
            String strZze = zze();
            parcel2.writeNoException();
            parcel2.writeString(strZze);
            return true;
        }
        if (i == 3) {
            boolean zF2 = f2();
            parcel2.writeNoException();
            ClassLoader classLoader = AbstractC2857y5.a;
            parcel2.writeInt(zF2 ? 1 : 0);
            return true;
        }
        if (i == 4) {
            String strF = f();
            parcel2.writeNoException();
            parcel2.writeString(strF);
            return true;
        }
        if (i != 5) {
            return false;
        }
        zzm zzmVar2 = (zzm) AbstractC2857y5.a(parcel, zzm.CREATOR);
        int i2 = parcel.readInt();
        AbstractC2857y5.b(parcel);
        B0(zzmVar2, i2);
        parcel2.writeNoException();
        return true;
    }
}

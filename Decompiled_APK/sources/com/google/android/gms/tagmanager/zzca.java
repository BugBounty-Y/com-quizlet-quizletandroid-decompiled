package com.google.android.gms.tagmanager;

import android.os.Parcel;
import android.os.RemoteException;
import com.google.android.gms.internal.gtm.zzas;
import com.google.android.gms.internal.gtm.zzat;
import java.util.HashMap;

/* loaded from: classes2.dex */
public abstract class zzca extends zzas implements zzcb {
    public zzca() {
        super("com.google.android.gms.tagmanager.ICustomEvaluatorProxy");
    }

    @Override // com.google.android.gms.internal.gtm.zzas
    public final boolean zza(int i, Parcel parcel, Parcel parcel2, int i2) throws RemoteException {
        if (i == 1) {
            String string = parcel.readString();
            HashMap mapZzb = zzat.zzb(parcel);
            zzat.zzc(parcel);
            zzc(string, mapZzb);
            parcel2.writeNoException();
        } else {
            if (i != 2) {
                return false;
            }
            String string2 = parcel.readString();
            HashMap mapZzb2 = zzat.zzb(parcel);
            zzat.zzc(parcel);
            String strZzb = zzb(string2, mapZzb2);
            parcel2.writeNoException();
            parcel2.writeString(strZzb);
        }
        return true;
    }
}

package com.google.android.gms.tagmanager;

import android.os.Bundle;
import android.os.Parcel;
import android.os.RemoteException;
import com.google.android.gms.internal.gtm.zzas;
import com.google.android.gms.internal.gtm.zzat;

/* loaded from: classes2.dex */
public abstract class zzcg extends zzas implements zzch {
    public zzcg() {
        super("com.google.android.gms.tagmanager.IMeasurementInterceptor");
    }

    @Override // com.google.android.gms.internal.gtm.zzas
    public final boolean zza(int i, Parcel parcel, Parcel parcel2, int i2) throws RemoteException {
        if (i != 2) {
            return false;
        }
        String string = parcel.readString();
        String string2 = parcel.readString();
        Bundle bundle = (Bundle) zzat.zza(parcel, Bundle.CREATOR);
        long j = parcel.readLong();
        zzat.zzc(parcel);
        zze(string, string2, bundle, j);
        parcel2.writeNoException();
        return true;
    }
}

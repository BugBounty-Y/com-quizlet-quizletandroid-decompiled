package com.google.android.gms.internal.gtm;

import android.os.Parcel;
import android.os.RemoteException;

/* loaded from: classes2.dex */
public abstract class zzhc extends zzas implements zzhd {
    public zzhc() {
        super("com.google.android.gms.tagmanager.internal.ITagManagerLoadContainerCallback");
    }

    @Override // com.google.android.gms.internal.gtm.zzas
    public final boolean zza(int i, Parcel parcel, Parcel parcel2, int i2) throws RemoteException {
        if (i != 1) {
            return false;
        }
        boolean zZzf = zzat.zzf(parcel);
        String string = parcel.readString();
        zzat.zzc(parcel);
        zze(zZzf, string);
        return true;
    }
}

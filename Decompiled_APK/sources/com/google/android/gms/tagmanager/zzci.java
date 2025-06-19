package com.google.android.gms.tagmanager;

import android.os.Bundle;
import android.os.IBinder;
import android.os.Parcel;
import android.os.RemoteException;
import com.google.android.gms.internal.gtm.zzar;
import com.google.android.gms.internal.gtm.zzat;
import java.util.HashMap;
import java.util.Map;

/* loaded from: classes2.dex */
public final class zzci extends zzar implements zzck {
    public zzci(IBinder iBinder) {
        super(iBinder, "com.google.android.gms.tagmanager.IMeasurementProxy");
    }

    @Override // com.google.android.gms.tagmanager.zzck
    public final Map zzb() throws RemoteException {
        Parcel parcelZzk = zzk(11, zza());
        HashMap mapZzb = zzat.zzb(parcelZzk);
        parcelZzk.recycle();
        return mapZzb;
    }

    @Override // com.google.android.gms.tagmanager.zzck
    public final void zzc(String str, String str2, Bundle bundle, long j) throws RemoteException {
        Parcel parcelZza = zza();
        parcelZza.writeString(str);
        parcelZza.writeString(str2);
        zzat.zzd(parcelZza, bundle);
        parcelZza.writeLong(j);
        zzl(2, parcelZza);
    }

    @Override // com.google.android.gms.tagmanager.zzck
    public final void zzd(zzce zzceVar) throws RemoteException {
        Parcel parcelZza = zza();
        zzat.zze(parcelZza, zzceVar);
        zzl(22, parcelZza);
    }

    @Override // com.google.android.gms.tagmanager.zzck
    public final void zze(zzch zzchVar) throws RemoteException {
        Parcel parcelZza = zza();
        zzat.zze(parcelZza, zzchVar);
        zzl(21, parcelZza);
    }
}

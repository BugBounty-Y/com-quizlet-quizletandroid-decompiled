package com.google.android.gms.internal.gtm;

import android.os.Bundle;
import android.os.IBinder;
import android.os.Parcel;
import android.os.RemoteException;

/* loaded from: classes2.dex */
public final class zzhe extends zzar implements zzhg {
    public zzhe(IBinder iBinder) {
        super(iBinder, "com.google.android.gms.tagmanager.internal.ITagManagerService");
    }

    @Override // com.google.android.gms.internal.gtm.zzhg
    public final void zze() throws RemoteException {
        zzl(102, zza());
    }

    @Override // com.google.android.gms.internal.gtm.zzhg
    public final void zzf(String str, Bundle bundle, String str2, long j, boolean z) throws RemoteException {
        Parcel parcelZza = zza();
        parcelZza.writeString(str);
        zzat.zzd(parcelZza, bundle);
        parcelZza.writeString(str2);
        parcelZza.writeLong(j);
        parcelZza.writeInt(z ? 1 : 0);
        zzl(101, parcelZza);
    }

    @Override // com.google.android.gms.internal.gtm.zzhg
    public final void zzh(String str, String str2, String str3, zzhd zzhdVar) throws RemoteException {
        Parcel parcelZza = zza();
        parcelZza.writeString(str);
        parcelZza.writeString(str2);
        parcelZza.writeString(null);
        zzat.zze(parcelZza, zzhdVar);
        zzl(2, parcelZza);
    }

    @Override // com.google.android.gms.internal.gtm.zzhg
    public final void zzi() throws RemoteException {
        zzl(3, zza());
    }
}

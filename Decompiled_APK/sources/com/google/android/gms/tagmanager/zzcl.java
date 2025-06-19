package com.google.android.gms.tagmanager;

import android.content.Intent;
import android.os.IBinder;
import android.os.Parcel;
import android.os.RemoteException;
import com.google.android.gms.dynamic.a;
import com.google.android.gms.internal.gtm.zzar;
import com.google.android.gms.internal.gtm.zzat;

/* loaded from: classes2.dex */
public final class zzcl extends zzar implements zzcn {
    public zzcl(IBinder iBinder) {
        super(iBinder, "com.google.android.gms.tagmanager.ITagManagerApi");
    }

    @Override // com.google.android.gms.tagmanager.zzcn
    public final void initialize(a aVar, zzck zzckVar, zzcb zzcbVar) throws RemoteException {
        Parcel parcelZza = zza();
        zzat.zze(parcelZza, aVar);
        zzat.zze(parcelZza, zzckVar);
        zzat.zze(parcelZza, zzcbVar);
        zzl(1, parcelZza);
    }

    @Override // com.google.android.gms.tagmanager.zzcn
    public final void previewIntent(Intent intent, a aVar, a aVar2, zzck zzckVar, zzcb zzcbVar) throws RemoteException {
        Parcel parcelZza = zza();
        zzat.zzd(parcelZza, intent);
        zzat.zze(parcelZza, aVar);
        zzat.zze(parcelZza, aVar2);
        zzat.zze(parcelZza, zzckVar);
        zzat.zze(parcelZza, zzcbVar);
        zzl(3, parcelZza);
    }
}

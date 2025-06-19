package com.google.android.gms.tagmanager;

import android.os.IBinder;
import android.os.Parcel;
import android.os.RemoteException;
import com.google.android.gms.dynamic.a;
import com.google.android.gms.internal.gtm.zzar;
import com.google.android.gms.internal.gtm.zzat;
import com.google.android.gms.internal.gtm.zzhf;
import com.google.android.gms.internal.gtm.zzhg;

/* loaded from: classes2.dex */
public final class zzco extends zzar implements zzcq {
    public zzco(IBinder iBinder) {
        super(iBinder, "com.google.android.gms.tagmanager.ITagManagerServiceProvider");
    }

    @Override // com.google.android.gms.tagmanager.zzcq
    public final zzhg getService(a aVar, zzck zzckVar, zzcb zzcbVar) throws RemoteException {
        Parcel parcelZza = zza();
        zzat.zze(parcelZza, aVar);
        zzat.zze(parcelZza, zzckVar);
        zzat.zze(parcelZza, zzcbVar);
        Parcel parcelZzk = zzk(1, parcelZza);
        zzhg zzhgVarZzb = zzhf.zzb(parcelZzk.readStrongBinder());
        parcelZzk.recycle();
        return zzhgVarZzb;
    }
}

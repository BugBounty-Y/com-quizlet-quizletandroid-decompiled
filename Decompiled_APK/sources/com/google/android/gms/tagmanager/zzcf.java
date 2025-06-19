package com.google.android.gms.tagmanager;

import android.os.Bundle;
import android.os.IBinder;
import android.os.Parcel;
import android.os.RemoteException;
import com.google.android.gms.internal.gtm.zzar;
import com.google.android.gms.internal.gtm.zzat;

/* loaded from: classes2.dex */
public final class zzcf extends zzar implements zzch {
    public zzcf(IBinder iBinder) {
        super(iBinder, "com.google.android.gms.tagmanager.IMeasurementInterceptor");
    }

    @Override // com.google.android.gms.tagmanager.zzch
    public final void zze(String str, String str2, Bundle bundle, long j) throws RemoteException {
        Parcel parcelZza = zza();
        parcelZza.writeString(str);
        parcelZza.writeString(str2);
        zzat.zzd(parcelZza, bundle);
        parcelZza.writeLong(j);
        zzl(2, parcelZza);
    }
}

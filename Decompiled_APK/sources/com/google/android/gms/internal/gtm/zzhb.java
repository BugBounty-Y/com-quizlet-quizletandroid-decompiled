package com.google.android.gms.internal.gtm;

import android.os.IBinder;
import android.os.Parcel;
import android.os.RemoteException;

/* loaded from: classes2.dex */
public final class zzhb extends zzar implements zzhd {
    public zzhb(IBinder iBinder) {
        super(iBinder, "com.google.android.gms.tagmanager.internal.ITagManagerLoadContainerCallback");
    }

    @Override // com.google.android.gms.internal.gtm.zzhd
    public final void zze(boolean z, String str) throws RemoteException {
        Parcel parcelZza = zza();
        int i = zzat.a;
        parcelZza.writeInt(z ? 1 : 0);
        parcelZza.writeString(str);
        zzm(1, parcelZza);
    }
}

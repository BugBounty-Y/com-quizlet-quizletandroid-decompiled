package com.google.android.gms.internal.gtm;

import android.os.RemoteException;

/* loaded from: classes2.dex */
final class zziv extends zzhc {
    final /* synthetic */ zzix zza;

    @Override // com.google.android.gms.internal.gtm.zzhd
    public final void zze(boolean z, String str) throws RemoteException {
        this.zza.zzf.execute(new zziu(this, z, str));
    }
}

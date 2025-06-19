package com.google.android.gms.internal.gtm;

import android.os.Bundle;
import android.os.RemoteException;

/* loaded from: classes2.dex */
final class zzik extends com.google.android.gms.tagmanager.zzcg {
    final /* synthetic */ zzix zza;

    public zzik(zzix zzixVar) {
        this.zza = zzixVar;
    }

    @Override // com.google.android.gms.tagmanager.zzch
    public final void zze(String str, String str2, Bundle bundle, long j) throws RemoteException {
        this.zza.zzf.execute(new zzij(this, str2, bundle, String.valueOf(str).concat("+gtm"), j, str));
    }
}

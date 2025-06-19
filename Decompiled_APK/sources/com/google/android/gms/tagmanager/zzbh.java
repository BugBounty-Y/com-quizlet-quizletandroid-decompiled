package com.google.android.gms.tagmanager;

import android.os.Bundle;
import android.os.RemoteException;
import com.google.android.gms.measurement.internal.InterfaceC3887p0;

/* loaded from: classes2.dex */
final class zzbh implements InterfaceC3887p0 {
    final /* synthetic */ zzce zza;

    public zzbh(zzbi zzbiVar, zzce zzceVar) {
        this.zza = zzceVar;
    }

    @Override // com.google.android.gms.measurement.internal.InterfaceC3887p0
    public final void onEvent(String str, String str2, Bundle bundle, long j) {
        try {
            this.zza.zze(str, str2, bundle, j);
        } catch (RemoteException e) {
            throw new IllegalStateException(e);
        }
    }
}

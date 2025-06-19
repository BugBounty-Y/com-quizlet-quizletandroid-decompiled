package com.google.android.gms.tagmanager;

import android.os.Bundle;
import android.os.RemoteException;
import com.google.android.gms.measurement.internal.InterfaceC3885o0;

/* loaded from: classes2.dex */
final class zzbg implements InterfaceC3885o0 {
    final /* synthetic */ zzch zza;

    public zzbg(zzbi zzbiVar, zzch zzchVar) {
        this.zza = zzchVar;
    }

    @Override // com.google.android.gms.measurement.internal.InterfaceC3885o0
    public final void interceptEvent(String str, String str2, Bundle bundle, long j) {
        try {
            this.zza.zze(str, str2, bundle, j);
        } catch (RemoteException e) {
            throw new IllegalStateException(e);
        }
    }
}

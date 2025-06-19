package com.google.android.gms.tagmanager;

import android.content.Context;
import android.content.Intent;
import android.content.res.Resources;
import android.os.RemoteException;
import androidx.annotation.NonNull;
import com.google.android.gms.common.util.DynamiteApi;
import com.google.android.gms.dynamic.a;
import com.google.android.gms.dynamic.b;
import com.google.android.gms.internal.gtm.zzhi;
import com.google.android.gms.internal.gtm.zzho;
import com.google.android.gms.internal.gtm.zzix;

@DynamiteApi
/* loaded from: classes2.dex */
public class TagManagerApiImpl extends zzcm {
    private zzix zza;

    @Override // com.google.android.gms.tagmanager.zzcn
    public void initialize(a aVar, zzck zzckVar, zzcb zzcbVar) throws RemoteException {
        zzix zzixVarZzf = zzix.zzf((Context) b.I3(aVar), zzckVar, zzcbVar);
        this.zza = zzixVarZzf;
        zzixVarZzf.zzm(null);
    }

    @Override // com.google.android.gms.tagmanager.zzcn
    @Deprecated
    public void preview(@NonNull Intent intent, @NonNull a aVar) {
        zzhi.zze("Deprecated. Please use previewIntent instead.");
    }

    @Override // com.google.android.gms.tagmanager.zzcn
    public void previewIntent(Intent intent, a aVar, a aVar2, zzck zzckVar, zzcb zzcbVar) throws Resources.NotFoundException {
        Context context = (Context) b.I3(aVar);
        Context context2 = (Context) b.I3(aVar2);
        zzix zzixVarZzf = zzix.zzf(context, zzckVar, zzcbVar);
        this.zza = zzixVarZzf;
        new zzho(intent, context, context2, zzixVarZzf).zzb();
    }
}

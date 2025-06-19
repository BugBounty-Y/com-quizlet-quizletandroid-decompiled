package com.google.android.gms.internal.gtm;

import android.content.Context;
import com.google.android.gms.analytics.a;
import com.google.android.gms.analytics.c;
import java.util.ArrayList;

/* loaded from: classes2.dex */
public final class zzji {
    private a zza;
    private final Context zzb;
    private c zzc;

    public zzji(Context context) {
        this.zzb = context;
    }

    private final synchronized void zzb(String str) {
        c cVar;
        if (this.zza == null) {
            Context context = this.zzb;
            ArrayList arrayList = a.g;
            a aVarZzc = zzbu.zzg(context).zzc();
            this.zza = aVarZzc;
            aVarZzc.t(new zzjh());
            a aVar = this.zza;
            synchronized (aVar) {
                cVar = new c((zzbu) aVar.c, "_GTM_DEFAULT_TRACKER_");
                cVar.zzW();
            }
            this.zzc = cVar;
        }
    }

    public final c zza(String str) {
        zzb("_GTM_DEFAULT_TRACKER_");
        return this.zzc;
    }
}

package com.google.android.gms.internal.gtm;

import com.google.android.gms.common.api.Status;
import com.google.android.gms.common.util.b;
import java.util.List;

/* loaded from: classes2.dex */
final class zzpc extends zzpa {
    final /* synthetic */ zzpe zze;
    private final zzpb zzf;
    private final List zzg;
    private final int zzh;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public zzpc(zzpe zzpeVar, int i, zzpj zzpjVar, zzpf zzpfVar, List list, int i2, zzpb zzpbVar, zzgo zzgoVar) {
        super(i, zzpjVar, zzpfVar, zzgoVar, b.a);
        this.zze = zzpeVar;
        this.zzf = zzpbVar;
        this.zzg = list;
        this.zzh = i2;
    }

    @Override // com.google.android.gms.internal.gtm.zzpa
    public final void zza(zzpl zzplVar) {
        if (zzplVar.getStatus() == Status.e) {
            zzhi.zzd("Container resource successfully loaded from ".concat(zzplVar.zzd()));
            if (zzplVar.zza() == 0) {
                zzpk zzpkVarZzb = zzplVar.zzb();
                if (!zzpkVarZzb.zzb().zzg()) {
                    this.zze.zzd(zzplVar.getStatus(), zzpkVarZzb);
                    if (zzpkVarZzb.zzd() != null && zzpkVarZzb.zzd().length > 0) {
                        this.zze.zzc.zzg(zzpkVarZzb.zzb().zzd(), zzpkVarZzb.zzd());
                    }
                }
            }
            this.zzf.zza(zzplVar);
            return;
        }
        zzhi.zzd("Cannot fetch a valid resource from " + zzplVar.zzd() + ". Response status: " + (true != zzplVar.getStatus().a() ? "FAILURE" : "SUCCESS"));
        if (zzplVar.getStatus().a()) {
            zzhi.zzd("Response source: ".concat(zzplVar.zzd()));
            zzhi.zzd("Response size: " + zzplVar.zzb().zzd().length);
        }
        this.zze.zzb(this.zza, this.zzg, this.zzh + 1, this.zzf, this.zzd);
    }
}

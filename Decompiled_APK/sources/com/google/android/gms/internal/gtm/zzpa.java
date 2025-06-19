package com.google.android.gms.internal.gtm;

import com.google.android.gms.common.api.Status;
import com.google.android.gms.common.internal.u;
import com.google.android.gms.common.util.a;

/* loaded from: classes2.dex */
public abstract class zzpa {
    protected final zzpj zza;
    protected final zzpf zzb;
    protected final a zzc;
    protected final zzgo zzd;
    private final int zze;

    public zzpa(int i, zzpj zzpjVar, zzpf zzpfVar, zzgo zzgoVar, a aVar) {
        u.h(zzpjVar);
        this.zza = zzpjVar;
        u.h(zzpjVar.zza());
        this.zze = i;
        u.h(zzpfVar);
        this.zzb = zzpfVar;
        u.h(aVar);
        this.zzc = aVar;
        this.zzd = zzgoVar;
    }

    public abstract void zza(zzpl zzplVar);

    public final void zzb(int i, int i2) {
        zzgo zzgoVar = this.zzd;
        if (zzgoVar != null && i2 == 0 && i == 3) {
            zzgoVar.zzd();
        }
        zzhi.zzd("Failed to fetch the container resource for the container \"" + this.zza.zza().zzb() + "\": " + (i != 0 ? i != 1 ? i != 2 ? "Unknown reason" : "Server error" : "IOError" : "Resource not available"));
        zza(new zzpl(Status.g, i2, null, null));
    }

    /* JADX WARN: Removed duplicated region for block: B:15:0x0049  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void zzc(byte[] r11) {
        /*
            r10 = this;
            r0 = 0
            com.google.android.gms.internal.gtm.zzpf r1 = r10.zzb     // Catch: com.google.android.gms.internal.gtm.zzoy -> L8
            com.google.android.gms.internal.gtm.zzpl r1 = r1.zza(r11)     // Catch: com.google.android.gms.internal.gtm.zzoy -> L8
            goto Le
        L8:
            java.lang.String r1 = "Resource data is corrupted"
            com.google.android.gms.internal.gtm.zzhi.zzc(r1)
            r1 = r0
        Le:
            com.google.android.gms.internal.gtm.zzgo r2 = r10.zzd
            if (r2 == 0) goto L19
            int r3 = r10.zze
            if (r3 != 0) goto L19
            r2.zze()
        L19:
            if (r1 == 0) goto L49
            com.google.android.gms.common.api.Status r2 = r1.getStatus()
            com.google.android.gms.common.api.Status r3 = com.google.android.gms.common.api.Status.e
            if (r2 != r3) goto L49
            com.google.android.gms.internal.gtm.zzpk r0 = r1.zzb()
            com.google.android.gms.internal.gtm.zzpy r7 = r0.zzc()
            com.google.android.gms.internal.gtm.zzpj r0 = r10.zza
            com.google.android.gms.common.util.a r2 = r10.zzc
            com.google.android.gms.internal.gtm.zzpk r4 = new com.google.android.gms.internal.gtm.zzpk
            com.google.android.gms.internal.gtm.zzox r5 = r0.zza()
            long r8 = r2.currentTimeMillis()
            r6 = r11
            r4.<init>(r5, r6, r7, r8)
            com.google.android.gms.internal.gtm.zzqh r11 = r1.zzc()
            int r0 = r10.zze
            com.google.android.gms.internal.gtm.zzpl r1 = new com.google.android.gms.internal.gtm.zzpl
            r1.<init>(r3, r0, r4, r11)
            goto L52
        L49:
            int r11 = r10.zze
            com.google.android.gms.internal.gtm.zzpl r1 = new com.google.android.gms.internal.gtm.zzpl
            com.google.android.gms.common.api.Status r2 = com.google.android.gms.common.api.Status.g
            r1.<init>(r2, r11, r0, r0)
        L52:
            r10.zza(r1)
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.gtm.zzpa.zzc(byte[]):void");
    }
}

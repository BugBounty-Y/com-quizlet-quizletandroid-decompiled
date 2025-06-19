package com.google.android.gms.internal.gtm;

import android.annotation.SuppressLint;
import android.content.Context;
import android.os.SystemClock;
import com.google.android.gms.analytics.j;
import com.google.android.gms.common.internal.u;
import com.google.android.gms.common.util.a;
import com.google.android.gms.common.util.b;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;

@SuppressLint({"StaticFieldLeak"})
/* loaded from: classes2.dex */
public final class zzbu {
    private static volatile zzbu zza;
    private final Context zzb;
    private final Context zzc;
    private final a zzd;
    private final zzcs zze;
    private final zzeo zzf;
    private final j zzg;
    private final zzbp zzh;
    private final zzcx zzi;
    private final zzfg zzj;
    private final zzeu zzk;
    private final com.google.android.gms.analytics.a zzl;
    private final zzcm zzm;
    private final zzbh zzn;
    private final zzce zzo;
    private final zzcw zzp;

    public zzbu(zzbv zzbvVar) {
        Context contextZza = zzbvVar.zza();
        u.i(contextZza, "Application context can't be null");
        Context contextZzb = zzbvVar.zzb();
        u.h(contextZzb);
        this.zzb = contextZza;
        this.zzc = contextZzb;
        this.zzd = b.a;
        this.zze = new zzcs(this);
        zzeo zzeoVar = new zzeo(this);
        zzeoVar.zzW();
        this.zzf = zzeoVar;
        zzm().zzL("Google Analytics " + zzbs.zza + " is starting up. To enable debug logging on a device run:\n  adb shell setprop log.tag.GAv4 DEBUG\n  adb logcat -s GAv4");
        zzeu zzeuVar = new zzeu(this);
        zzeuVar.zzW();
        this.zzk = zzeuVar;
        zzfg zzfgVar = new zzfg(this);
        zzfgVar.zzW();
        this.zzj = zzfgVar;
        zzbp zzbpVar = new zzbp(this, zzbvVar);
        zzcm zzcmVar = new zzcm(this);
        zzbh zzbhVar = new zzbh(this);
        zzce zzceVar = new zzce(this);
        zzcw zzcwVar = new zzcw(this);
        if (j.e == null) {
            synchronized (j.class) {
                try {
                    if (j.e == null) {
                        j.e = new j(contextZza);
                    }
                } finally {
                }
            }
        }
        j jVar = j.e;
        jVar.d = new zzbt(this);
        this.zzg = jVar;
        com.google.android.gms.analytics.a aVar = new com.google.android.gms.analytics.a(this);
        new HashSet();
        zzcmVar.zzW();
        this.zzm = zzcmVar;
        zzbhVar.zzW();
        this.zzn = zzbhVar;
        zzceVar.zzW();
        this.zzo = zzceVar;
        zzcwVar.zzW();
        this.zzp = zzcwVar;
        zzcx zzcxVar = new zzcx(this);
        zzcxVar.zzW();
        this.zzi = zzcxVar;
        zzbpVar.zzW();
        this.zzh = zzbpVar;
        zzfg zzfgVarZzq = ((zzbu) aVar.c).zzq();
        zzfgVarZzq.zzf();
        if (zzfgVarZzq.zze()) {
            aVar.e = zzfgVarZzq.zzc();
        }
        zzfgVarZzq.zzf();
        aVar.d = true;
        this.zzl = aVar;
        zzbpVar.zzm();
    }

    public static zzbu zzg(Context context) {
        u.h(context);
        if (zza == null) {
            synchronized (zzbu.class) {
                if (zza == null) {
                    long jElapsedRealtime = SystemClock.elapsedRealtime();
                    zzbu zzbuVar = new zzbu(new zzbv(context));
                    zza = zzbuVar;
                    ArrayList arrayList = com.google.android.gms.analytics.a.g;
                    synchronized (com.google.android.gms.analytics.a.class) {
                        try {
                            ArrayList arrayList2 = com.google.android.gms.analytics.a.g;
                            if (arrayList2 != null) {
                                Iterator it2 = arrayList2.iterator();
                                while (it2.hasNext()) {
                                    ((Runnable) it2.next()).run();
                                }
                                com.google.android.gms.analytics.a.g = null;
                            }
                        } finally {
                        }
                    }
                    long jElapsedRealtime2 = SystemClock.elapsedRealtime() - jElapsedRealtime;
                    Long l = (Long) zzeh.zzE.zzb();
                    if (jElapsedRealtime2 > l.longValue()) {
                        zzbuVar.zzm().zzS("Slow initialization (ms)", Long.valueOf(jElapsedRealtime2), l);
                    }
                }
            }
        }
        return zza;
    }

    private static final void zzs(zzbr zzbrVar) {
        u.i(zzbrVar, "Analytics service not created/initialized");
        u.a("Analytics service not initialized", zzbrVar.zzX());
    }

    public final Context zza() {
        return this.zzb;
    }

    public final Context zzb() {
        return this.zzc;
    }

    public final com.google.android.gms.analytics.a zzc() {
        u.h(this.zzl);
        u.a("Analytics instance not initialized", this.zzl.d);
        return this.zzl;
    }

    public final j zzd() {
        u.h(this.zzg);
        return this.zzg;
    }

    public final zzbh zze() {
        zzs(this.zzn);
        return this.zzn;
    }

    public final zzbp zzf() {
        zzs(this.zzh);
        return this.zzh;
    }

    public final zzce zzh() {
        zzs(this.zzo);
        return this.zzo;
    }

    public final zzcm zzi() {
        zzs(this.zzm);
        return this.zzm;
    }

    public final zzcs zzj() {
        return this.zze;
    }

    public final zzcw zzk() {
        return this.zzp;
    }

    public final zzcx zzl() {
        zzs(this.zzi);
        return this.zzi;
    }

    public final zzeo zzm() {
        zzs(this.zzf);
        return this.zzf;
    }

    public final zzeo zzn() {
        return this.zzf;
    }

    public final zzeu zzo() {
        zzs(this.zzk);
        return this.zzk;
    }

    public final zzeu zzp() {
        zzeu zzeuVar = this.zzk;
        if (zzeuVar == null || !zzeuVar.zzX()) {
            return null;
        }
        return zzeuVar;
    }

    public final zzfg zzq() {
        zzs(this.zzj);
        return this.zzj;
    }

    public final a zzr() {
        return this.zzd;
    }
}

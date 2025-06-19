package com.google.android.gms.analytics;

import android.os.Bundle;
import android.text.TextUtils;
import com.google.android.gms.common.internal.u;
import com.google.android.gms.internal.gtm.zzau;
import com.google.android.gms.internal.gtm.zzbh;
import com.google.android.gms.internal.gtm.zzbs;
import com.google.android.gms.internal.gtm.zzbu;
import com.google.android.gms.internal.gtm.zzbw;
import com.google.android.gms.internal.gtm.zzek;
import com.google.android.gms.internal.gtm.zzff;
import com.google.android.gms.measurement.internal.D0;
import java.lang.reflect.InvocationTargetException;
import java.util.HashMap;

/* loaded from: classes2.dex */
public final class l implements Runnable {
    public final /* synthetic */ int a = 0;
    public final /* synthetic */ String b;
    public final /* synthetic */ String c;
    public final /* synthetic */ long d;
    public final /* synthetic */ boolean e;
    public final /* synthetic */ boolean f;
    public final /* synthetic */ boolean g;
    public final /* synthetic */ Cloneable h;
    public final /* synthetic */ Object i;

    public l(c cVar, HashMap map, boolean z, String str, long j, boolean z2, boolean z3, String str2) {
        this.h = map;
        this.e = z;
        this.b = str;
        this.d = j;
        this.f = z2;
        this.g = z3;
        this.c = str2;
        this.i = cVar;
    }

    @Override // java.lang.Runnable
    public final void run() throws IllegalAccessException, ClassNotFoundException, IllegalArgumentException, InvocationTargetException {
        double d;
        switch (this.a) {
            case 0:
                synchronized (((c) this.i).e) {
                }
                HashMap map = (HashMap) this.h;
                a aVarZzp = ((c) this.i).zzp();
                u.g("getClientId can not be called from the main thread");
                String strZzb = ((zzbu) aVarZzp.c).zzi().zzb();
                if (strZzb != null && TextUtils.isEmpty((CharSequence) map.get("cid"))) {
                    map.put("cid", strZzb);
                }
                String str = (String) ((HashMap) this.h).get("sf");
                if (str != null) {
                    try {
                        d = Double.parseDouble(str);
                    } catch (NumberFormatException unused) {
                        d = 100.0d;
                    }
                    if (zzff.zzj(d, (String) ((HashMap) this.h).get("cid"))) {
                        ((c) this.i).zzF("Sampling enabled. Hit sampled out. sample rate", Double.valueOf(d));
                        break;
                    }
                }
                c cVar = (c) this.i;
                boolean z = this.e;
                zzbh zzbhVarZzr = cVar.zzr();
                if (z) {
                    HashMap map2 = (HashMap) this.h;
                    boolean zZzb = zzbhVarZzr.zzb();
                    if (!map2.containsKey("ate")) {
                        map2.put("ate", true != zZzb ? "0" : "1");
                    }
                    zzff.zzg((HashMap) this.h, "adid", zzbhVarZzr.zza());
                } else {
                    ((HashMap) this.h).remove("ate");
                    ((HashMap) this.h).remove("adid");
                }
                zzau zzauVarZza = ((c) this.i).zzu().zza();
                zzff.zzg((HashMap) this.h, "an", zzauVarZza.zzf());
                zzff.zzg((HashMap) this.h, "av", zzauVarZza.zzg());
                zzff.zzg((HashMap) this.h, "aid", zzauVarZza.zzd());
                zzff.zzg((HashMap) this.h, "aiid", zzauVarZza.zze());
                ((HashMap) this.h).put("v", "1");
                ((HashMap) this.h).put("_v", zzbs.zzb);
                zzff.zzg((HashMap) this.h, "ul", ((c) this.i).zzx().zza().zzd());
                zzff.zzg((HashMap) this.h, "sr", ((c) this.i).zzx().zzb());
                if (!this.b.equals("transaction") && !this.b.equals("item") && !((c) this.i).d.zza()) {
                    ((c) this.i).zzz().zzc((HashMap) this.h, "Too many hits sent too quickly, rate limiting invoked");
                    break;
                } else {
                    long jZza = zzff.zza((String) ((HashMap) this.h).get("ht"));
                    if (jZza == 0) {
                        jZza = this.d;
                    }
                    long j = jZza;
                    if (!this.f) {
                        String str2 = (String) ((HashMap) this.h).get("cid");
                        HashMap map3 = new HashMap();
                        zzff.zzh(map3, "uid", (HashMap) this.h);
                        zzff.zzh(map3, "an", (HashMap) this.h);
                        zzff.zzh(map3, "aid", (HashMap) this.h);
                        zzff.zzh(map3, "av", (HashMap) this.h);
                        zzff.zzh(map3, "aiid", (HashMap) this.h);
                        u.h(str2);
                        ((HashMap) this.h).put("_s", String.valueOf(((c) this.i).zzs().zza(new zzbw(0L, str2, this.c, !TextUtils.isEmpty((CharSequence) ((HashMap) this.h).get("adid")), 0L, map3))));
                        ((c) this.i).zzs().zzh(new zzek((c) this.i, (HashMap) this.h, j, this.g));
                        break;
                    } else {
                        ((c) this.i).zzz().zzM("Dry run enabled. Would have sent hit", new zzek((c) this.i, (HashMap) this.h, j, this.g));
                        break;
                    }
                }
                break;
            default:
                ((D0) this.i).e0(this.b, this.c, this.d, (Bundle) this.h, this.e, this.f, this.g);
                break;
        }
    }

    public l(D0 d0, String str, String str2, long j, Bundle bundle, boolean z, boolean z2, boolean z3) {
        this.b = str;
        this.c = str2;
        this.d = j;
        this.h = bundle;
        this.e = z;
        this.f = z2;
        this.g = z3;
        this.i = d0;
    }
}

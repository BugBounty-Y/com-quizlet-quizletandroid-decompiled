package com.google.android.gms.internal.gtm;

import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteException;
import android.net.Uri;
import android.support.v4.media.session.a;
import android.text.TextUtils;
import androidx.work.impl.model.e;
import com.google.android.gms.analytics.CampaignTrackingReceiver;
import com.google.android.gms.analytics.d;
import com.google.android.gms.analytics.f;
import com.google.android.gms.analytics.j;
import com.google.android.gms.analytics.k;
import com.google.android.gms.common.internal.u;
import com.quizlet.data.repository.course.membership.c;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.ListIterator;
import java.util.Map;

/* loaded from: classes2.dex */
final class zzcj extends zzbr {
    private boolean zza;
    private final zzcd zzb;
    private final zzer zzc;
    private final zzep zzd;
    private final zzcb zze;
    private long zzf;
    private final zzcv zzg;
    private final zzcv zzh;
    private final zzfb zzi;
    private long zzj;
    private boolean zzk;

    public zzcj(zzbu zzbuVar, zzbv zzbvVar) {
        super(zzbuVar);
        u.h(zzbvVar);
        this.zzf = Long.MIN_VALUE;
        this.zzd = new zzep(zzbuVar);
        this.zzb = new zzcd(zzbuVar);
        this.zzc = new zzer(zzbuVar);
        this.zze = new zzcb(zzbuVar);
        this.zzi = new zzfb(zzC());
        this.zzg = new zzcf(this, zzbuVar);
        this.zzh = new zzcg(this, zzbuVar);
    }

    private final void zzaf() {
        zzcx zzcxVarZzy = zzy();
        if (zzcxVarZzy.zze()) {
            zzcxVarZzy.zza();
        }
    }

    private final void zzag() {
        if (this.zzg.zzh()) {
            zzN("All hits dispatched or no network/service. Going to power save mode");
        }
        this.zzg.zzf();
    }

    private final void zzah() {
        long jZzc;
        zzcx zzcxVarZzy = zzy();
        if (zzcxVarZzy.zzc() && !zzcxVarZzy.zze()) {
            j.a();
            zzV();
            try {
                jZzc = this.zzb.zzc();
            } catch (SQLiteException e) {
                zzJ("Failed to get min/max hit times from local store", e);
                jZzc = 0;
            }
            if (jZzc != 0) {
                long jAbs = Math.abs(zzC().currentTimeMillis() - jZzc);
                zzw();
                if (jAbs <= ((Long) zzeh.zzh.zzb()).longValue()) {
                    zzw();
                    zzO("Dispatch alarm scheduled (ms)", Long.valueOf(zzcs.zzd()));
                    zzcxVarZzy.zzb();
                }
            }
        }
    }

    private final void zzai(zzbw zzbwVar, zzav zzavVar) {
        u.h(zzbwVar);
        u.h(zzavVar);
        c cVar = new c(zzt());
        String strZzc = zzbwVar.zzc();
        u.e(strZzc);
        u.e(strZzc);
        Uri.Builder builder = new Uri.Builder();
        builder.scheme("uri");
        builder.authority("google-analytics.com");
        builder.path(strZzc);
        Uri uriBuild = builder.build();
        e eVar = (e) cVar.a;
        ListIterator listIterator = ((ArrayList) eVar.c).listIterator();
        while (listIterator.hasNext()) {
            if (uriBuild.equals(((k) listIterator.next()).zzb())) {
                listIterator.remove();
            }
        }
        ArrayList arrayList = (ArrayList) eVar.c;
        zzbu zzbuVar = (zzbu) cVar.c;
        arrayList.add(new d(zzbuVar, strZzc));
        zzbwVar.zzf();
        new ArrayList(arrayList);
        HashMap map = (HashMap) eVar.b;
        HashMap map2 = new HashMap(map.size());
        for (Map.Entry entry : map.entrySet()) {
            f fVarX = e.x((Class) entry.getKey());
            ((f) entry.getValue()).zzc(fVarX);
            map2.put((Class) entry.getKey(), fVarX);
        }
        zzau zzauVarZza = zzbuVar.zzh().zza();
        u.h(zzauVarZza);
        if (zzau.class.getSuperclass() != f.class) {
            throw new IllegalArgumentException();
        }
        f fVarX2 = (f) map2.get(zzau.class);
        if (fVarX2 == null) {
            fVarX2 = e.x(zzau.class);
            map2.put(zzau.class, fVarX2);
        }
        zzauVarZza.zzc(fVarX2);
        zzaz zzazVarZza = zzbuVar.zzk().zza();
        u.h(zzazVarZza);
        if (zzaz.class.getSuperclass() != f.class) {
            throw new IllegalArgumentException();
        }
        f fVarX3 = (f) map2.get(zzaz.class);
        if (fVarX3 == null) {
            fVarX3 = e.x(zzaz.class);
            map2.put(zzaz.class, fVarX3);
        }
        zzazVarZza.zzc(fVarX3);
        Iterator it2 = ((ArrayList) cVar.b).iterator();
        if (it2.hasNext()) {
            throw a.d(it2);
        }
        f fVarX4 = (f) map2.get(zzbd.class);
        if (fVarX4 == null) {
            fVarX4 = e.x(zzbd.class);
            map2.put(zzbd.class, fVarX4);
        }
        fVarX4.getClass();
        throw new ClassCastException();
    }

    private final boolean zzaj(String str) {
        return com.google.android.gms.common.wrappers.c.a(zzo()).a.checkCallingOrSelfPermission(str) == 0;
    }

    public static /* bridge */ /* synthetic */ void zzc(zzcj zzcjVar) {
        try {
            zzcjVar.zzb.zza();
            zzcjVar.zzad();
        } catch (SQLiteException e) {
            zzcjVar.zzR("Failed to delete stale hits", e);
        }
        zzcv zzcvVar = zzcjVar.zzh;
        zzcjVar.zzw();
        zzcvVar.zzg(86400000L);
    }

    public final void zzZ() {
        zzV();
        u.j("Analytics backend already started", !this.zza);
        this.zza = true;
        j jVarZzq = zzq();
        zzch zzchVar = new zzch(this);
        jVarZzq.getClass();
        jVarZzq.b.submit(zzchVar);
    }

    public final long zza() {
        long j = this.zzf;
        if (j != Long.MIN_VALUE) {
            return j;
        }
        zzw();
        long jLongValue = ((Long) zzeh.zze.zzb()).longValue();
        zzfg zzfgVarZzB = zzB();
        zzfgVarZzB.zzV();
        if (!zzfgVarZzB.zzc) {
            return jLongValue;
        }
        zzB().zzV();
        return r0.zzd * 1000;
    }

    public final void zzaa() {
        zzV();
        zzw();
        j.a();
        Context contextZza = zzt().zza();
        if (!zzev.zzb(contextZza)) {
            zzQ("AnalyticsReceiver is not registered or is disabled. Register the receiver for reliable dispatching on non-Google Play devices. See http://goo.gl/8Rd3yj for instructions.");
        } else if (!zzfa.zzh(contextZza)) {
            zzI("AnalyticsService is not registered or is disabled. Analytics service at risk of not starting. See http://goo.gl/8Rd3yj for instructions.");
        }
        if (!CampaignTrackingReceiver.zzb(contextZza)) {
            zzQ("CampaignTrackingReceiver is not registered, not exported or is disabled. Installation campaign tracking is not possible. See http://goo.gl/8Rd3yj for instructions.");
        }
        zzA().zza();
        if (!zzaj("android.permission.ACCESS_NETWORK_STATE")) {
            zzI("Missing required android.permission.ACCESS_NETWORK_STATE. Google Analytics disabled. See http://goo.gl/8Rd3yj for instructions");
            zzac();
        }
        if (!zzaj("android.permission.INTERNET")) {
            zzI("Missing required android.permission.INTERNET. Google Analytics disabled. See http://goo.gl/8Rd3yj for instructions");
            zzac();
        }
        if (zzfa.zzh(zzo())) {
            zzN("AnalyticsService registered in the app manifest and enabled");
        } else {
            zzw();
            zzQ("AnalyticsService not registered in the app manifest. Hits might not be delivered reliably. See http://goo.gl/8Rd3yj for instructions.");
        }
        if (!this.zzk) {
            zzw();
            if (!this.zzb.zzab()) {
                zzi();
            }
        }
        zzad();
    }

    public final void zzac() {
        zzV();
        j.a();
        this.zzk = true;
        this.zze.zzc();
        zzad();
    }

    public final void zzad() {
        long jMin;
        j.a();
        zzV();
        if (!this.zzk) {
            zzw();
            if (zza() > 0) {
                if (this.zzb.zzab()) {
                    this.zzd.zzc();
                    zzag();
                    zzaf();
                    return;
                }
                if (!((Boolean) zzeh.zzz.zzb()).booleanValue()) {
                    this.zzd.zza();
                    if (!this.zzd.zzd()) {
                        zzag();
                        zzaf();
                        zzah();
                        return;
                    }
                }
                zzah();
                long jZza = zza();
                long jZzb = zzA().zzb();
                if (jZzb != 0) {
                    jMin = jZza - Math.abs(zzC().currentTimeMillis() - jZzb);
                    if (jMin <= 0) {
                        zzw();
                        jMin = Math.min(zzcs.zze(), jZza);
                    }
                } else {
                    zzw();
                    jMin = Math.min(zzcs.zze(), jZza);
                }
                zzO("Dispatch scheduled (ms)", Long.valueOf(jMin));
                if (!this.zzg.zzh()) {
                    this.zzg.zzg(jMin);
                    return;
                } else {
                    this.zzg.zze(Math.max(1L, jMin + this.zzg.zzb()));
                    return;
                }
            }
        }
        this.zzd.zzc();
        zzag();
        zzaf();
    }

    /* JADX WARN: Code restructure failed: missing block: B:16:0x0059, code lost:
    
        zzN("Store is empty, nothing to dispatch");
        zzag();
        zzaf();
     */
    /* JADX WARN: Code restructure failed: missing block: B:29:0x00b0, code lost:
    
        if (r11.zze.zzg() == false) goto L41;
     */
    /* JADX WARN: Code restructure failed: missing block: B:30:0x00b2, code lost:
    
        zzw();
        zzN("Service connected, sending hits to the service");
     */
    /* JADX WARN: Code restructure failed: missing block: B:32:0x00be, code lost:
    
        if (r6.isEmpty() != false) goto L78;
     */
    /* JADX WARN: Code restructure failed: missing block: B:33:0x00c0, code lost:
    
        r7 = (com.google.android.gms.internal.gtm.zzek) r6.get(0);
     */
    /* JADX WARN: Code restructure failed: missing block: B:34:0x00cc, code lost:
    
        if (r11.zze.zzh(r7) != false) goto L36;
     */
    /* JADX WARN: Code restructure failed: missing block: B:36:0x00cf, code lost:
    
        r4 = java.lang.Math.max(r4, r7.zzb());
        r6.remove(r7);
        zzF("Hit sent do device AnalyticsService for delivery", r7);
     */
    /* JADX WARN: Code restructure failed: missing block: B:37:0x00df, code lost:
    
        r11.zzb.zzn(r7.zzb());
        r0.add(java.lang.Long.valueOf(r7.zzb()));
     */
    /* JADX WARN: Code restructure failed: missing block: B:39:0x00f4, code lost:
    
        r0 = move-exception;
     */
    /* JADX WARN: Code restructure failed: missing block: B:40:0x00f5, code lost:
    
        zzJ("Failed to remove hit that was send for delivery", r0);
        zzag();
        zzaf();
     */
    /* JADX WARN: Code restructure failed: missing block: B:42:0x0107, code lost:
    
        if (r11.zzc.zze() == false) goto L52;
     */
    /* JADX WARN: Code restructure failed: missing block: B:43:0x0109, code lost:
    
        r6 = r11.zzc.zzc(r6);
        r7 = r6.iterator();
     */
    /* JADX WARN: Code restructure failed: missing block: B:45:0x0117, code lost:
    
        if (r7.hasNext() == false) goto L71;
     */
    /* JADX WARN: Code restructure failed: missing block: B:46:0x0119, code lost:
    
        r4 = java.lang.Math.max(r4, ((java.lang.Long) r7.next()).longValue());
     */
    /* JADX WARN: Code restructure failed: missing block: B:48:0x0128, code lost:
    
        r11.zzb.zzY(r6);
        r0.addAll(r6);
     */
    /* JADX WARN: Code restructure failed: missing block: B:50:0x0131, code lost:
    
        r0 = move-exception;
     */
    /* JADX WARN: Code restructure failed: missing block: B:51:0x0132, code lost:
    
        zzJ("Failed to remove successfully uploaded hits", r0);
        zzag();
        zzaf();
     */
    /* JADX WARN: Code restructure failed: missing block: B:53:0x0142, code lost:
    
        if (r0.isEmpty() != false) goto L75;
     */
    /* JADX WARN: Code restructure failed: missing block: B:56:0x0150, code lost:
    
        r0 = move-exception;
     */
    /* JADX WARN: Code restructure failed: missing block: B:63:0x0173, code lost:
    
        zzJ("Failed to commit local dispatch transaction", r0);
        zzag();
        zzaf();
     */
    /* JADX WARN: Code restructure failed: missing block: B:64:0x017e, code lost:
    
        return false;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final boolean zzae() {
        /*
            Method dump skipped, instructions count: 383
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.gtm.zzcj.zzae():boolean");
    }

    public final long zzb(zzbw zzbwVar, boolean z) {
        u.h(zzbwVar);
        zzV();
        j.a();
        long j = -1;
        try {
            try {
                this.zzb.zzm();
                zzcd zzcdVar = this.zzb;
                String strZzb = zzbwVar.zzb();
                u.e(strZzb);
                zzcdVar.zzV();
                j.a();
                int iDelete = zzcdVar.zzf().delete("properties", "app_uid=? AND cid<>?", new String[]{"0", strZzb});
                if (iDelete > 0) {
                    zzcdVar.zzO("Deleted property records", Integer.valueOf(iDelete));
                }
                long jZze = this.zzb.zze(0L, zzbwVar.zzb(), zzbwVar.zzc());
                zzbwVar.zze(1 + jZze);
                zzcd zzcdVar2 = this.zzb;
                zzcdVar2.zzV();
                j.a();
                SQLiteDatabase sQLiteDatabaseZzf = zzcdVar2.zzf();
                Map mapZzd = zzbwVar.zzd();
                u.h(mapZzd);
                Uri.Builder builder = new Uri.Builder();
                for (Map.Entry entry : mapZzd.entrySet()) {
                    builder.appendQueryParameter((String) entry.getKey(), (String) entry.getValue());
                }
                String encodedQuery = builder.build().getEncodedQuery();
                if (encodedQuery == null) {
                    encodedQuery = "";
                }
                ContentValues contentValues = new ContentValues();
                contentValues.put("app_uid", (Long) 0L);
                contentValues.put("cid", zzbwVar.zzb());
                contentValues.put("tid", zzbwVar.zzc());
                contentValues.put("adid", Integer.valueOf(zzbwVar.zzf() ? 1 : 0));
                contentValues.put("hits_count", Long.valueOf(zzbwVar.zza()));
                contentValues.put("params", encodedQuery);
                try {
                    if (sQLiteDatabaseZzf.insertWithOnConflict("properties", null, contentValues, 5) == -1) {
                        zzcdVar2.zzI("Failed to insert/update a property (got -1)");
                    }
                } catch (SQLiteException e) {
                    zzcdVar2.zzJ("Error storing a property", e);
                }
                this.zzb.zzaa();
                j = jZze;
            } catch (SQLiteException e2) {
                zzJ("Failed to update Analytics property", e2);
            }
            try {
                this.zzb.zzZ();
            } catch (SQLiteException e3) {
                zzJ("Failed to end transaction", e3);
            }
            return j;
        } catch (Throwable th) {
            try {
                this.zzb.zzZ();
            } catch (SQLiteException e4) {
                zzJ("Failed to end transaction", e4);
            }
            throw th;
        }
    }

    @Override // com.google.android.gms.internal.gtm.zzbr
    public final void zzd() {
        this.zzb.zzW();
        this.zzc.zzW();
        this.zze.zzW();
    }

    public final void zzf(zzcy zzcyVar) {
        zzg(zzcyVar, this.zzj);
    }

    public final void zzg(zzcy zzcyVar, long j) {
        j.a();
        zzV();
        long jZzb = zzA().zzb();
        zzF("Dispatching local hits. Elapsed time since last dispatch (ms)", Long.valueOf(jZzb != 0 ? Math.abs(zzC().currentTimeMillis() - jZzb) : -1L));
        zzw();
        zzi();
        try {
            zzae();
            zzA().zzi();
            zzad();
            if (zzcyVar != null) {
                zzcyVar.zza(null);
            }
            if (this.zzj != j) {
                this.zzd.zzb();
            }
        } catch (Exception e) {
            zzJ("Local dispatch failed", e);
            zzA().zzi();
            zzad();
            if (zzcyVar != null) {
                zzcyVar.zza(e);
            }
        }
    }

    public final void zzi() {
        if (this.zzk) {
            return;
        }
        zzw();
        if (!zzcs.zzl() || this.zze.zzg()) {
            return;
        }
        zzw();
        if (this.zzi.zzc(((Long) zzeh.zzC.zzb()).longValue())) {
            this.zzi.zzb();
            zzN("Connecting to service");
            if (this.zze.zzf()) {
                zzN("Connected to service");
                this.zzi.zza();
                zzm();
            }
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:68:0x01be A[Catch: SQLiteException -> 0x00c9, TryCatch #1 {SQLiteException -> 0x00c9, blocks: (B:16:0x0079, B:17:0x0095, B:19:0x009b, B:21:0x00af, B:23:0x00b7, B:25:0x00bf, B:28:0x00cc, B:31:0x00d8, B:33:0x00e1, B:79:0x01f5, B:34:0x00ec, B:36:0x0107, B:38:0x0118, B:62:0x0179, B:39:0x011b, B:50:0x0165, B:64:0x018c, B:65:0x018f, B:66:0x0190, B:68:0x01be, B:70:0x01cd, B:78:0x01f0, B:69:0x01c6, B:71:0x01d2, B:73:0x01de, B:76:0x01e6), top: B:85:0x0079, inners: #2 }] */
    /* JADX WARN: Removed duplicated region for block: B:69:0x01c6 A[Catch: SQLiteException -> 0x00c9, TryCatch #1 {SQLiteException -> 0x00c9, blocks: (B:16:0x0079, B:17:0x0095, B:19:0x009b, B:21:0x00af, B:23:0x00b7, B:25:0x00bf, B:28:0x00cc, B:31:0x00d8, B:33:0x00e1, B:79:0x01f5, B:34:0x00ec, B:36:0x0107, B:38:0x0118, B:62:0x0179, B:39:0x011b, B:50:0x0165, B:64:0x018c, B:65:0x018f, B:66:0x0190, B:68:0x01be, B:70:0x01cd, B:78:0x01f0, B:69:0x01c6, B:71:0x01d2, B:73:0x01de, B:76:0x01e6), top: B:85:0x0079, inners: #2 }] */
    /* JADX WARN: Removed duplicated region for block: B:73:0x01de A[Catch: SQLiteException -> 0x01e4, TryCatch #2 {SQLiteException -> 0x01e4, blocks: (B:71:0x01d2, B:73:0x01de, B:76:0x01e6), top: B:87:0x01d2, outer: #1 }] */
    /* JADX WARN: Removed duplicated region for block: B:76:0x01e6 A[Catch: SQLiteException -> 0x01e4, TRY_LEAVE, TryCatch #2 {SQLiteException -> 0x01e4, blocks: (B:71:0x01d2, B:73:0x01de, B:76:0x01e6), top: B:87:0x01d2, outer: #1 }] */
    /* JADX WARN: Type inference failed for: r2v0, types: [java.lang.String] */
    /* JADX WARN: Type inference failed for: r2v11, types: [android.database.Cursor] */
    /* JADX WARN: Type inference failed for: r2v6 */
    /* JADX WARN: Type inference failed for: r2v7 */
    /* JADX WARN: Type inference failed for: r2v8 */
    /* JADX WARN: Type inference failed for: r2v9, types: [android.database.Cursor] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void zzj(com.google.android.gms.internal.gtm.zzek r20) throws java.lang.Throwable {
        /*
            Method dump skipped, instructions count: 520
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.gtm.zzcj.zzj(com.google.android.gms.internal.gtm.zzek):void");
    }

    public final void zzk(zzbw zzbwVar) {
        j.a();
        zzF("Sending first hit to property", zzbwVar.zzc());
        zzfb zzfbVarZzf = zzA().zzf();
        zzw();
        if (zzfbVarZzf.zzc(zzcs.zzc())) {
            return;
        }
        String strZzg = zzA().zzg();
        if (TextUtils.isEmpty(strZzg)) {
            return;
        }
        zzav zzavVarZzb = zzff.zzb(zzz(), strZzg);
        zzF("Found relevant installation campaign", zzavVarZzb);
        zzai(zzbwVar, zzavVarZzb);
    }

    public final void zzl() {
        j.a();
        this.zzj = zzC().currentTimeMillis();
    }

    public final void zzm() {
        j.a();
        zzw();
        j.a();
        zzV();
        zzw();
        zzw();
        if (!zzcs.zzl()) {
            zzQ("Service client disabled. Can't dispatch local hits to device AnalyticsService");
        }
        if (!this.zze.zzg()) {
            zzN("Service not connected");
            return;
        }
        if (this.zzb.zzab()) {
            return;
        }
        zzN("Dispatching local hits to device AnalyticsService");
        while (true) {
            try {
                zzcd zzcdVar = this.zzb;
                zzw();
                List listZzj = zzcdVar.zzj(zzcs.zzh());
                if (listZzj.isEmpty()) {
                    zzad();
                    return;
                }
                while (!listZzj.isEmpty()) {
                    zzek zzekVar = (zzek) listZzj.get(0);
                    if (!this.zze.zzh(zzekVar)) {
                        zzad();
                        return;
                    }
                    listZzj.remove(zzekVar);
                    try {
                        this.zzb.zzn(zzekVar.zzb());
                    } catch (SQLiteException e) {
                        zzJ("Failed to remove hit that was send for delivery", e);
                        zzag();
                        zzaf();
                        return;
                    }
                }
            } catch (SQLiteException e2) {
                zzJ("Failed to read hits from store", e2);
                zzag();
                zzaf();
                return;
            }
        }
    }

    public final void zzn(String str) {
        u.e(str);
        j.a();
        zzw();
        zzav zzavVarZzb = zzff.zzb(zzz(), str);
        if (zzavVarZzb == null) {
            zzR("Parsing failed. Ignoring invalid campaign data", str);
            return;
        }
        String strZzg = zzA().zzg();
        if (str.equals(strZzg)) {
            zzQ("Ignoring duplicate install campaign");
            return;
        }
        if (!TextUtils.isEmpty(strZzg)) {
            zzK("Ignoring multiple install campaigns. original, new", strZzg, str);
            return;
        }
        zzA().zzh(str);
        zzfb zzfbVarZzf = zzA().zzf();
        zzw();
        if (zzfbVarZzf.zzc(zzcs.zzc())) {
            zzR("Campaign received too late, ignoring", zzavVarZzb);
            return;
        }
        zzF("Received installation campaign", zzavVarZzb);
        zzcd zzcdVar = this.zzb;
        zzcdVar.zzV();
        j.a();
        SQLiteDatabase sQLiteDatabaseZzf = zzcdVar.zzf();
        Cursor cursorQuery = null;
        try {
            try {
                zzcdVar.zzw();
                int iIntValue = ((Integer) zzeh.zzd.zzb()).intValue();
                cursorQuery = sQLiteDatabaseZzf.query("properties", new String[]{"cid", "tid", "adid", "hits_count", "params"}, "app_uid=?", new String[]{"0"}, null, null, null, String.valueOf(iIntValue));
                ArrayList arrayList = new ArrayList();
                if (cursorQuery.moveToFirst()) {
                    do {
                        String string = cursorQuery.getString(0);
                        String string2 = cursorQuery.getString(1);
                        boolean z = cursorQuery.getInt(2) != 0;
                        long j = cursorQuery.getInt(3);
                        Map mapZzl = zzcdVar.zzl(cursorQuery.getString(4));
                        if (TextUtils.isEmpty(string) || TextUtils.isEmpty(string2)) {
                            zzcdVar.zzS("Read property with empty client id or tracker id", string, string2);
                        } else {
                            arrayList.add(new zzbw(0L, string, string2, z, j, mapZzl));
                        }
                    } while (cursorQuery.moveToNext());
                }
                if (arrayList.size() >= iIntValue) {
                    zzcdVar.zzQ("Sending hits to too many properties. Campaign report might be incorrect");
                }
                cursorQuery.close();
                Iterator it2 = arrayList.iterator();
                while (it2.hasNext()) {
                    zzai((zzbw) it2.next(), zzavVarZzb);
                }
            } catch (SQLiteException e) {
                zzcdVar.zzJ("Error loading hits from the database", e);
                throw e;
            }
        } catch (Throwable th) {
            if (cursorQuery != null) {
                cursorQuery.close();
            }
            throw th;
        }
    }
}

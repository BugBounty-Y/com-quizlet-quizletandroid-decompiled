package com.google.android.gms.internal.gtm;

import android.annotation.SuppressLint;
import android.content.Context;
import android.content.SharedPreferences;
import com.google.android.gms.common.internal.u;
import java.util.Random;

/* loaded from: classes2.dex */
public final class zzgo {
    private final Context zza;
    private final Random zzb;
    private final String zzc;

    public zzgo(Context context, String str) {
        Random random = new Random();
        u.h(context);
        this.zza = context;
        u.h(str);
        this.zzc = str;
        this.zzb = random;
    }

    private final long zzg(long j, long j2) {
        long jMax = Math.max(0L, zzh().getLong("FORBIDDEN_COUNT", 0L));
        return (long) (this.zzb.nextFloat() * (j + ((long) ((jMax / ((jMax + Math.max(0L, r0.getLong("SUCCESSFUL_COUNT", 0L))) + 1)) * (j2 - j)))));
    }

    private final SharedPreferences zzh() {
        return this.zza.getSharedPreferences("v5_gtmContainerRefreshPolicy_".concat(String.valueOf(this.zzc)), 0);
    }

    public final long zza() {
        if (Math.max(0L, zzh().getLong("FORBIDDEN_COUNT", 0L)) == 0) {
            return 0L;
        }
        return zzg(10000L, 600000L) + 10000;
    }

    public final long zzb() {
        return zzg(7200000L, 259200000L) + 43200000;
    }

    public final long zzc() {
        return zzg(600000L, 86400000L) + 3600000;
    }

    @SuppressLint({"CommitPrefEdits"})
    public final void zzd() {
        SharedPreferences sharedPreferencesZzh = zzh();
        long j = sharedPreferencesZzh.getLong("FORBIDDEN_COUNT", 0L);
        long j2 = sharedPreferencesZzh.getLong("SUCCESSFUL_COUNT", 0L);
        SharedPreferences.Editor editorEdit = sharedPreferencesZzh.edit();
        long jMin = j == 0 ? 3L : Math.min(10L, j + 1);
        long jMax = Math.max(0L, Math.min(j2, 10 - jMin));
        editorEdit.putLong("FORBIDDEN_COUNT", jMin);
        editorEdit.putLong("SUCCESSFUL_COUNT", jMax);
        editorEdit.apply();
    }

    @SuppressLint({"CommitPrefEdits"})
    public final void zze() {
        SharedPreferences sharedPreferencesZzh = zzh();
        long j = sharedPreferencesZzh.getLong("SUCCESSFUL_COUNT", 0L);
        long j2 = sharedPreferencesZzh.getLong("FORBIDDEN_COUNT", 0L);
        long jMin = Math.min(10L, j + 1);
        long jMax = Math.max(0L, Math.min(j2, 10 - jMin));
        SharedPreferences.Editor editorEdit = sharedPreferencesZzh.edit();
        editorEdit.putLong("SUCCESSFUL_COUNT", jMin);
        editorEdit.putLong("FORBIDDEN_COUNT", jMax);
        editorEdit.apply();
    }

    public final boolean zzf() {
        return Math.max(0L, zzh().getLong("FORBIDDEN_COUNT", 0L)) > 0;
    }
}

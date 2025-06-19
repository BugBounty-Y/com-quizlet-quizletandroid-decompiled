package com.google.android.gms.internal.gtm;

import android.content.SharedPreferences;
import android.util.Pair;
import com.google.android.gms.common.internal.u;
import java.util.UUID;

/* loaded from: classes2.dex */
public final class zzes {
    final /* synthetic */ zzeu zza;
    private final String zzb;
    private final long zzc;

    public /* synthetic */ zzes(zzeu zzeuVar, String str, long j, zzet zzetVar) {
        this.zza = zzeuVar;
        u.e("monitoring");
        u.b(j > 0);
        this.zzb = "monitoring";
        this.zzc = j;
    }

    private final long zzd() {
        return this.zza.zza.getLong(zzf(), 0L);
    }

    private final String zze() {
        return this.zzb.concat(":count");
    }

    private final String zzf() {
        return this.zzb.concat(":start");
    }

    private final void zzg() {
        long jCurrentTimeMillis = this.zza.zzC().currentTimeMillis();
        SharedPreferences.Editor editorEdit = this.zza.zza.edit();
        editorEdit.remove(zze());
        editorEdit.remove(zzb());
        editorEdit.putLong(zzf(), jCurrentTimeMillis);
        editorEdit.commit();
    }

    public final Pair zza() {
        long jZzd = zzd();
        long jAbs = jZzd == 0 ? 0L : Math.abs(jZzd - this.zza.zzC().currentTimeMillis());
        long j = this.zzc;
        if (jAbs >= j) {
            if (jAbs > j + j) {
                zzg();
                return null;
            }
            String string = this.zza.zza.getString(zzb(), null);
            long j2 = this.zza.zza.getLong(zze(), 0L);
            zzg();
            if (string != null && j2 > 0) {
                return new Pair(string, Long.valueOf(j2));
            }
        }
        return null;
    }

    public final String zzb() {
        return this.zzb.concat(":value");
    }

    public final void zzc(String str) {
        if (zzd() == 0) {
            zzg();
        }
        if (str == null) {
            str = "";
        }
        synchronized (this) {
            try {
                long j = this.zza.zza.getLong(zze(), 0L);
                if (j <= 0) {
                    SharedPreferences.Editor editorEdit = this.zza.zza.edit();
                    editorEdit.putString(zzb(), str);
                    editorEdit.putLong(zze(), 1L);
                    editorEdit.apply();
                    return;
                }
                long leastSignificantBits = UUID.randomUUID().getLeastSignificantBits() & Long.MAX_VALUE;
                long j2 = j + 1;
                long j3 = Long.MAX_VALUE / j2;
                SharedPreferences.Editor editorEdit2 = this.zza.zza.edit();
                if (leastSignificantBits < j3) {
                    editorEdit2.putString(zzb(), str);
                }
                editorEdit2.putLong(zze(), j2);
                editorEdit2.apply();
            } catch (Throwable th) {
                throw th;
            }
        }
    }
}

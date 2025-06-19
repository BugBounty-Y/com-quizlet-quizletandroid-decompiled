package com.google.android.gms.internal.gtm;

import com.google.android.gms.common.internal.u;
import java.util.Map;

/* loaded from: classes2.dex */
public final class zzeo extends zzbr {
    private static zzeo zza;

    public zzeo(zzbu zzbuVar) {
        super(zzbuVar);
    }

    public static zzeo zza() {
        return zza;
    }

    public static final String zzf(Object obj) {
        if (obj == null) {
            return null;
        }
        if (obj instanceof Integer) {
            obj = Long.valueOf(((Integer) obj).intValue());
        }
        if (!(obj instanceof Long)) {
            return obj instanceof Boolean ? obj.toString() : obj instanceof Throwable ? obj.getClass().getCanonicalName() : "-";
        }
        Long l = (Long) obj;
        if (Math.abs(l.longValue()) < 100) {
            return obj.toString();
        }
        char cCharAt = obj.toString().charAt(0);
        String strValueOf = String.valueOf(Math.abs(l.longValue()));
        StringBuilder sb = new StringBuilder();
        String str = cCharAt != '-' ? "" : "-";
        sb.append(str);
        sb.append(Math.round(Math.pow(10.0d, strValueOf.length() - 1)));
        sb.append("...");
        sb.append(str);
        sb.append(Math.round(Math.pow(10.0d, strValueOf.length()) - 1.0d));
        return sb.toString();
    }

    public final void zzb(zzek zzekVar, String str) {
        zzR("Discarding hit. ".concat(str), zzekVar != null ? zzekVar.toString() : "no hit data");
    }

    public final void zzc(Map map, String str) {
        StringBuilder sb = new StringBuilder();
        for (Map.Entry entry : map.entrySet()) {
            if (sb.length() > 0) {
                sb.append(',');
            }
            sb.append((String) entry.getKey());
            sb.append('=');
            sb.append((String) entry.getValue());
        }
        zzR("Discarding hit. ".concat(str), sb.toString());
    }

    @Override // com.google.android.gms.internal.gtm.zzbr
    public final void zzd() {
        synchronized (zzeo.class) {
            zza = this;
        }
    }

    public final synchronized void zze(int i, String str, Object obj, Object obj2, Object obj3) {
        char c;
        try {
            u.h(str);
            if (zzw().zzb()) {
                zzw();
                c = 'C';
            } else {
                zzw();
                c = 'c';
            }
            String strSubstring = "3" + "01VDIWEA?".charAt(i) + c + zzbs.zza + ":" + zzbq.zzD(str, zzf(obj), zzf(obj2), zzf(obj3));
            if (strSubstring.length() > 1024) {
                strSubstring = strSubstring.substring(0, 1024);
            }
            zzeu zzeuVarZzp = zzt().zzp();
            if (zzeuVarZzp != null) {
                zzeuVarZzp.zze().zzc(strSubstring);
            }
        } catch (Throwable th) {
            throw th;
        }
    }
}

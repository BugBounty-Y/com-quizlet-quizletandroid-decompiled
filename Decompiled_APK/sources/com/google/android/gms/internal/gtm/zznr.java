package com.google.android.gms.internal.gtm;

import android.util.Base64;
import com.google.android.gms.common.internal.u;

/* loaded from: classes2.dex */
public final class zznr extends zzjo {
    @Override // com.google.android.gms.internal.gtm.zzjo
    public final zzqo zza(zzhx zzhxVar, zzqo... zzqoVarArr) {
        byte[] bArrDecode;
        String strEncodeToString;
        int length = zzqoVarArr.length;
        u.b(length > 0);
        String strZzd = zzjn.zzd(zzqoVarArr[0]);
        String strZzd2 = length > 1 ? zzjn.zzd(zzqoVarArr[1]) : "text";
        int i = 2;
        String strZzd3 = length > 2 ? zzjn.zzd(zzqoVarArr[2]) : "base16";
        if (length > 3 && zzjn.zzg(zzqoVarArr[3])) {
            i = 3;
        }
        try {
            if ("text".equals(strZzd2)) {
                bArrDecode = strZzd.getBytes();
            } else if ("base16".equals(strZzd2)) {
                bArrDecode = zzgd.zzb(strZzd);
            } else if ("base64".equals(strZzd2)) {
                bArrDecode = Base64.decode(strZzd, i);
            } else {
                if (!"base64url".equals(strZzd2)) {
                    throw new UnsupportedOperationException("Encode: unknown input format: " + strZzd2);
                }
                bArrDecode = Base64.decode(strZzd, i | 8);
            }
            if ("base16".equals(strZzd3)) {
                strEncodeToString = zzgd.zza(bArrDecode);
            } else if ("base64".equals(strZzd3)) {
                strEncodeToString = Base64.encodeToString(bArrDecode, i);
            } else {
                if (!"base64url".equals(strZzd3)) {
                    throw new RuntimeException("Encode: unknown output format: ".concat(String.valueOf(strZzd3)));
                }
                strEncodeToString = Base64.encodeToString(bArrDecode, i | 8);
            }
            return new zzqz(strEncodeToString);
        } catch (IllegalArgumentException unused) {
            throw new RuntimeException("Encode: invalid input:".concat(String.valueOf(strZzd2)));
        }
    }
}

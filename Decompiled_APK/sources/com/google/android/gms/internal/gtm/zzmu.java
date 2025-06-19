package com.google.android.gms.internal.gtm;

import com.google.android.gms.common.internal.u;
import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;

/* loaded from: classes2.dex */
public final class zzmu extends zzjo {
    public static String zzb(String str, String str2) throws UnsupportedEncodingException {
        int i;
        StringBuilder sb = new StringBuilder();
        Charset charsetForName = Charset.forName("UTF-8");
        int i2 = 0;
        while (i2 < str.length()) {
            char cCharAt = str.charAt(i2);
            if (str2.indexOf(cCharAt) != -1) {
                sb.append(cCharAt);
                i2++;
            } else {
                if (Character.isHighSurrogate(cCharAt)) {
                    int i3 = i2 + 1;
                    if (i3 >= str.length()) {
                        throw new UnsupportedEncodingException();
                    }
                    if (!Character.isLowSurrogate(str.charAt(i3))) {
                        throw new UnsupportedEncodingException();
                    }
                    i = 2;
                } else {
                    i = 1;
                }
                int i4 = i + i2;
                byte[] bytes = str.substring(i2, i4).getBytes(charsetForName);
                for (int i5 = 0; i5 < bytes.length; i5++) {
                    sb.append("%");
                    sb.append(Character.toUpperCase(Character.forDigit((bytes[i5] >> 4) & 15, 16)));
                    sb.append(Character.toUpperCase(Character.forDigit(bytes[i5] & 15, 16)));
                }
                i2 = i4;
            }
        }
        return sb.toString().replaceAll(" ", "%20");
    }

    @Override // com.google.android.gms.internal.gtm.zzjo
    public final zzqo zza(zzhx zzhxVar, zzqo... zzqoVarArr) {
        zzqo zzqoVar;
        if (zzqoVarArr.length > 0) {
            zzqoVar = zzqoVarArr[0];
            u.h(zzqoVar);
        } else {
            zzqoVar = zzqs.zze;
        }
        try {
            return new zzqz(zzb(zzjn.zzd(zzqoVar), "#;/?:@&=+$,abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-_.!~*'()0123456789"));
        } catch (UnsupportedEncodingException unused) {
            return zzqs.zze;
        }
    }
}

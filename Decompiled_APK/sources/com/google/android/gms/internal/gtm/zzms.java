package com.google.android.gms.internal.gtm;

import com.google.android.gms.common.internal.u;
import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;

/* loaded from: classes2.dex */
public final class zzms extends zzjo {
    public static String zzb(String str, String str2) throws UnsupportedEncodingException {
        Charset charsetForName = Charset.forName("UTF-8");
        StringBuilder sb = new StringBuilder();
        int i = 0;
        while (i < str.length()) {
            char cCharAt = str.charAt(i);
            if (cCharAt != '%') {
                sb.append(cCharAt);
                i++;
            } else {
                byte bZzc = zzc(str, i);
                int i2 = i + 3;
                if ((bZzc & 128) != 0) {
                    int i3 = 0;
                    while (((bZzc << i3) & 128) != 0) {
                        i3++;
                    }
                    if (i3 < 2 || i3 > 4) {
                        throw new UnsupportedEncodingException();
                    }
                    byte[] bArr = new byte[i3];
                    bArr[0] = bZzc;
                    for (int i4 = 1; i4 < i3; i4++) {
                        byte bZzc2 = zzc(str, i2);
                        i2 += 3;
                        if ((bZzc2 & 192) != 128) {
                            throw new UnsupportedEncodingException();
                        }
                        bArr[i4] = bZzc2;
                    }
                    CharBuffer charBufferDecode = charsetForName.decode(ByteBuffer.wrap(bArr));
                    if (charBufferDecode.length() != 1 || str2.indexOf(charBufferDecode.charAt(0)) == -1) {
                        sb.append((CharSequence) charBufferDecode);
                    } else {
                        sb.append(str.substring(i, i2));
                    }
                } else if (str2.indexOf(bZzc) == -1) {
                    sb.append((char) bZzc);
                } else {
                    sb.append(str.substring(i, i2));
                }
                i = i2;
            }
        }
        return sb.toString();
    }

    private static byte zzc(String str, int i) throws UnsupportedEncodingException {
        int i2 = i + 3;
        if (i2 > str.length() || str.charAt(i) != '%') {
            throw new UnsupportedEncodingException();
        }
        String strSubstring = str.substring(i + 1, i2);
        if (strSubstring.charAt(0) == '+' || strSubstring.charAt(0) == '-') {
            throw new UnsupportedEncodingException();
        }
        try {
            return (byte) Integer.parseInt(strSubstring, 16);
        } catch (NumberFormatException unused) {
            throw new UnsupportedEncodingException();
        }
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
            return new zzqz(zzb(zzjn.zzd(zzqoVar), "#;/?:@&=+$,"));
        } catch (UnsupportedEncodingException unused) {
            return zzqs.zze;
        }
    }
}

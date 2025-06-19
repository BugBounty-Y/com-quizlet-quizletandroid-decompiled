package com.google.android.gms.internal.gtm;

import com.google.android.gms.common.internal.u;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/* loaded from: classes2.dex */
public final class zzns extends zzjo {
    private static final Pattern zza = Pattern.compile("(.+)/(.+)/(.+)");

    @Override // com.google.android.gms.internal.gtm.zzjo
    public final zzqo zza(zzhx zzhxVar, zzqo... zzqoVarArr) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException {
        int length = zzqoVarArr.length;
        u.b(length >= 3);
        u.b(zzqoVarArr[1] instanceof zzqz);
        String strZzd = zzjn.zzd(zzqoVarArr[0]);
        String strZzd2 = zzjn.zzd(zzqoVarArr[1]);
        String strZzd3 = zzjn.zzd(zzqoVarArr[2]);
        String strZzd4 = length < 4 ? "AES/CBC/NoPadding" : zzjn.zzd(zzqoVarArr[3]);
        Matcher matcher = zza.matcher(strZzd4);
        if (!matcher.matches()) {
            throw new RuntimeException("Encrypt: invalid transformation:".concat(String.valueOf(strZzd4)));
        }
        SecretKeySpec secretKeySpec = new SecretKeySpec(strZzd2.getBytes(), matcher.group(1));
        IvParameterSpec ivParameterSpec = new IvParameterSpec(strZzd3.getBytes());
        try {
            Cipher cipher = Cipher.getInstance(strZzd4);
            if (strZzd == null || strZzd.length() == 0) {
                throw new RuntimeException("Encrypt: empty input string");
            }
            try {
                cipher.init(1, secretKeySpec, ivParameterSpec);
                return new zzqz(zzgd.zza(cipher.doFinal(strZzd.getBytes())));
            } catch (Exception e) {
                throw new RuntimeException("Encrypt: ".concat(String.valueOf(e.getMessage())));
            }
        } catch (NoSuchAlgorithmException | NoSuchPaddingException unused) {
            throw new RuntimeException("Encrypt: invalid transformation:".concat(String.valueOf(strZzd4)));
        }
    }
}

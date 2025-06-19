package com.google.android.gms.internal.gtm;

import com.google.android.gms.common.internal.u;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/* loaded from: classes2.dex */
public final class zznv extends zzjo {
    @Override // com.google.android.gms.internal.gtm.zzjo
    public final zzqo zza(zzhx zzhxVar, zzqo... zzqoVarArr) throws NoSuchAlgorithmException {
        byte[] bArrZzb;
        zzqo zzqoVar;
        zzqo zzqoVar2;
        int length = zzqoVarArr.length;
        u.b(length > 0);
        zzqo zzqoVar3 = zzqoVarArr[0];
        zzqs zzqsVar = zzqs.zze;
        if (zzqoVar3 == zzqsVar) {
            return zzqsVar;
        }
        String strZzd = zzjn.zzd(zzqoVar3);
        String strZzd2 = "MD5";
        if (length > 1 && (zzqoVar2 = zzqoVarArr[1]) != zzqsVar) {
            strZzd2 = zzjn.zzd(zzqoVar2);
        }
        String strZzd3 = (length <= 2 || (zzqoVar = zzqoVarArr[2]) == zzqsVar) ? "text" : zzjn.zzd(zzqoVar);
        if ("text".equals(strZzd3)) {
            bArrZzb = strZzd.getBytes();
        } else {
            if (!"base16".equals(strZzd3)) {
                throw new RuntimeException("Hash: Unknown input format: ".concat(String.valueOf(strZzd3)));
            }
            bArrZzb = zzgd.zzb(strZzd);
        }
        try {
            MessageDigest messageDigest = MessageDigest.getInstance(strZzd2);
            messageDigest.update(bArrZzb);
            return new zzqz(zzgd.zza(messageDigest.digest()));
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Hash: Unknown algorithm: ".concat(String.valueOf(strZzd2)), e);
        }
    }
}

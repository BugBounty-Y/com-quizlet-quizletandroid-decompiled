package com.google.android.gms.internal.gtm;

import com.google.android.gms.common.internal.u;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/* loaded from: classes2.dex */
public final class zzof extends zzjo {
    @Override // com.google.android.gms.internal.gtm.zzjo
    public final zzqo zza(zzhx zzhxVar, zzqo... zzqoVarArr) throws NumberFormatException {
        zzqo zzqoVar;
        zzqo zzqoVar2;
        int length = zzqoVarArr.length;
        int i = 1;
        u.b(length >= 2);
        zzqo zzqoVar3 = zzqoVarArr[0];
        zzqs zzqsVar = zzqs.zze;
        if (zzqoVar3 != zzqsVar && zzqoVarArr[1] != zzqsVar) {
            String strZzd = zzjn.zzd(zzqoVar3);
            String strZzd2 = zzjn.zzd(zzqoVarArr[1]);
            int i2 = 64;
            if (length > 2 && (zzqoVar2 = zzqoVarArr[2]) != zzqsVar && zzjn.zzg(zzqoVar2)) {
                i2 = 66;
            }
            if (length > 3 && (zzqoVar = zzqoVarArr[3]) != zzqsVar) {
                if (zzqoVar instanceof zzqq) {
                    double dZza = zzjn.zza(zzqoVar);
                    if (!Double.isInfinite(dZza) && dZza >= 0.0d) {
                        i = (int) dZza;
                    }
                    return zzqs.zze;
                }
            }
            try {
                Matcher matcher = Pattern.compile(strZzd2, i2).matcher(strZzd);
                String strGroup = null;
                if (matcher.find() && matcher.groupCount() >= i) {
                    strGroup = matcher.group(i);
                }
                if (strGroup != null) {
                    return new zzqz(strGroup);
                }
            } catch (PatternSyntaxException unused) {
            }
        }
        return zzqsVar;
    }
}

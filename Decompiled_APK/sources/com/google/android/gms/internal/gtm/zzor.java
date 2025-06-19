package com.google.android.gms.internal.gtm;

import com.google.android.gms.common.internal.u;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/* loaded from: classes2.dex */
public final class zzor extends zzjo {
    @Override // com.google.android.gms.internal.gtm.zzjo
    public final zzqo zza(zzhx zzhxVar, zzqo... zzqoVarArr) {
        boolean z;
        int length = zzqoVarArr.length;
        if (length == 2) {
            z = true;
        } else if (length == 3) {
            z = true;
            length = 3;
        } else {
            z = false;
        }
        u.b(z);
        String strZzd = zzjn.zzd(zzqoVarArr[0]);
        String strZzd2 = zzjn.zzd(zzqoVarArr[1]);
        int i = 64;
        if (length >= 3 && "true".equalsIgnoreCase(zzjn.zzd(zzqoVarArr[2]))) {
            i = 66;
        }
        try {
            return new zzqp(Boolean.valueOf(Pattern.compile(strZzd2, i).matcher(strZzd).find()));
        } catch (PatternSyntaxException unused) {
            return new zzqp(Boolean.FALSE);
        }
    }
}

package com.google.android.gms.internal.gtm;

import com.google.android.gms.common.internal.u;
import java.util.regex.Pattern;

/* loaded from: classes2.dex */
public final class zzmi extends zzjo {
    @Override // com.google.android.gms.internal.gtm.zzjo
    public final zzqo zza(zzhx zzhxVar, zzqo... zzqoVarArr) {
        boolean z;
        int length = zzqoVarArr.length;
        if (length == 1) {
            z = true;
        } else if (length == 2) {
            length = 2;
            z = true;
        } else {
            z = false;
        }
        u.b(z);
        u.b(zzqoVarArr[0] instanceof zzqz);
        return Pattern.compile(length < 2 ? "" : zzjn.zzd(zzqoVarArr[1])).matcher(((zzqz) zzqoVarArr[0]).zzk()).find() ? new zzqq(Double.valueOf(r5.start())) : new zzqq(Double.valueOf(-1.0d));
    }
}

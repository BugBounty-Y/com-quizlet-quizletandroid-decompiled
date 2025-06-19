package com.google.android.gms.internal.gtm;

import android.text.TextUtils;
import com.google.android.gms.common.internal.u;
import java.util.ArrayList;
import java.util.List;

/* loaded from: classes2.dex */
public final class zzju extends zzjo {
    @Override // com.google.android.gms.internal.gtm.zzjo
    public final zzqo zza(zzhx zzhxVar, zzqo... zzqoVarArr) {
        boolean z;
        u.h(zzqoVarArr);
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
        u.b(zzqoVarArr[0] instanceof zzqv);
        List<zzqo> listZzk = ((zzqv) zzqoVarArr[0]).zzk();
        zzqo zzqoVar = length < 2 ? zzqs.zze : zzqoVarArr[1];
        String strZzd = zzqoVar == zzqs.zze ? "," : zzjn.zzd(zzqoVar);
        ArrayList arrayList = new ArrayList();
        for (zzqo zzqoVar2 : listZzk) {
            if (zzqoVar2 == zzqs.zzd || zzqoVar2 == zzqs.zze) {
                arrayList.add("");
            } else {
                arrayList.add(zzjn.zzd(zzqoVar2));
            }
        }
        return new zzqz(TextUtils.join(strZzd, arrayList));
    }
}

package com.google.android.gms.internal.gtm;

import com.google.android.gms.common.internal.u;
import java.util.ArrayList;

/* loaded from: classes2.dex */
public final class zzmk extends zzjo {
    @Override // com.google.android.gms.internal.gtm.zzjo
    public final zzqo zza(zzhx zzhxVar, zzqo... zzqoVarArr) {
        boolean z;
        int length = zzqoVarArr.length;
        int i = 0;
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
        ArrayList arrayList = new ArrayList();
        if (length == 1) {
            arrayList.add(zzqoVarArr[0]);
        } else {
            String strZzk = ((zzqz) zzqoVarArr[0]).zzk();
            String strZzd = zzjn.zzd(zzqoVarArr[1]);
            boolean zIsEmpty = strZzd.isEmpty();
            String[] strArrSplit = strZzk.split(strZzd, true != zIsEmpty ? -1 : 0);
            if (zIsEmpty && strArrSplit.length > 0 && strArrSplit[0].isEmpty()) {
                i = 1;
            }
            while (i < strArrSplit.length) {
                arrayList.add(new zzqz(strArrSplit[i]));
                i++;
            }
        }
        return new zzqv(arrayList);
    }
}

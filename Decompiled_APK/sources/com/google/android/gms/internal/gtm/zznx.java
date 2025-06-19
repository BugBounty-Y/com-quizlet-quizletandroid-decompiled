package com.google.android.gms.internal.gtm;

import com.amazon.device.ads.DTBMetricsConfiguration;
import com.google.android.gms.common.internal.u;
import com.j256.ormlite.stmt.query.SimpleComparison;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;

/* loaded from: classes2.dex */
public final class zznx extends zzjo {
    private static final void zzb(Set set, String str) {
        for (int i = 0; i < str.length(); i++) {
            set.add(Character.valueOf(str.charAt(i)));
        }
    }

    private static final String zzc(String str, int i, Set set) {
        if (i == 1) {
            try {
                return URLEncoder.encode(str, "UTF-8").replaceAll("\\+", "%20");
            } catch (UnsupportedEncodingException unused) {
                return str;
            }
        }
        if (i != 2) {
            return str;
        }
        String strReplace = str.replace("\\", "\\\\");
        Iterator it2 = set.iterator();
        while (it2.hasNext()) {
            String string = ((Character) it2.next()).toString();
            strReplace = strReplace.replace(string, "\\".concat(String.valueOf(string)));
        }
        return strReplace;
    }

    @Override // com.google.android.gms.internal.gtm.zzjo
    public final zzqo zza(zzhx zzhxVar, zzqo... zzqoVarArr) {
        zzqo zzqoVar;
        zzqo zzqoVar2;
        int length = zzqoVarArr.length;
        boolean z = true;
        u.b(length > 0);
        zzqo zzqoVar3 = zzqoVarArr[0];
        zzqo zzqoVar4 = length > 1 ? zzqoVarArr[1] : zzqs.zze;
        int i = 2;
        String strZzd = (length <= 2 || (zzqoVar2 = zzqoVarArr[2]) == zzqs.zze) ? "" : zzjn.zzd(zzqoVar2);
        String strZzd2 = SimpleComparison.EQUAL_TO_OPERATION;
        if (length > 3 && (zzqoVar = zzqoVarArr[3]) != zzqs.zze) {
            strZzd2 = zzjn.zzd(zzqoVar);
        }
        HashSet hashSet = null;
        if (zzqoVar4 != zzqs.zze) {
            u.b(zzqoVar4 instanceof zzqz);
            if (DTBMetricsConfiguration.APSMETRICS_URL.equals(zzqoVar4.zzc())) {
                i = 1;
            } else {
                if (!"backslash".equals(zzqoVar4.zzc())) {
                    return new zzqz("");
                }
                hashSet = new HashSet();
                zzb(hashSet, strZzd);
                zzb(hashSet, strZzd2);
                hashSet.remove('\\');
            }
        } else {
            i = 0;
        }
        StringBuilder sb = new StringBuilder();
        if (zzqoVar3 instanceof zzqv) {
            for (zzqo zzqoVar5 : ((zzqv) zzqoVar3).zzk()) {
                if (!z) {
                    sb.append(strZzd);
                }
                sb.append(zzc(zzjn.zzd(zzqoVar5), i, hashSet));
                z = false;
            }
        } else if (zzqoVar3 instanceof zzqw) {
            Map mapZzi = ((zzqw) zzqoVar3).zzi();
            for (String str : mapZzi.keySet()) {
                if (!z) {
                    sb.append(strZzd);
                }
                String strZzd3 = zzjn.zzd((zzqo) mapZzi.get(str));
                sb.append(zzc(str, i, hashSet));
                sb.append(strZzd2);
                sb.append(zzc(strZzd3, i, hashSet));
                z = false;
            }
        } else {
            sb.append(zzc(zzjn.zzd(zzqoVar3), i, hashSet));
        }
        return new zzqz(sb.toString());
    }
}

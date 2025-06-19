package com.google.android.gms.internal.gtm;

import android.support.v4.media.session.a;
import com.amazon.device.ads.DTBMetricsConfiguration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

/* loaded from: classes2.dex */
public abstract class zzjk {
    public static final /* synthetic */ int a = 0;
    private static final Map zzb;

    static {
        HashMap map = new HashMap();
        map.put(zza.CONTAINS.toString(), new zzjj("contains"));
        map.put(zza.ENDS_WITH.toString(), new zzjj("endsWith"));
        map.put(zza.EQUALS.toString(), new zzjj("equals"));
        map.put(zza.GREATER_EQUALS.toString(), new zzjj("greaterEquals"));
        map.put(zza.GREATER_THAN.toString(), new zzjj("greaterThan"));
        map.put(zza.LESS_EQUALS.toString(), new zzjj("lessEquals"));
        map.put(zza.LESS_THAN.toString(), new zzjj("lessThan"));
        map.put(zza.REGEX.toString(), new zzjj("regex", new String[]{zzb.ARG0.toString(), zzb.ARG1.toString(), zzb.IGNORE_CASE.toString()}));
        map.put(zza.STARTS_WITH.toString(), new zzjj("startsWith"));
        zzb = map;
    }

    public static zzqx zza(String str, Map map, zzhx zzhxVar) {
        Map map2 = zzb;
        if (!map2.containsKey(str)) {
            throw new RuntimeException(a.B("Fail to convert ", str, " to the internal representation"));
        }
        zzjj zzjjVar = (zzjj) map2.get(str);
        String[] strArrZzb = zzjjVar.zzb();
        ArrayList arrayList = new ArrayList();
        for (int i = 0; i < strArrZzb.length; i++) {
            if (map.containsKey(strArrZzb[i])) {
                arrayList.add((zzqo) map.get(strArrZzb[i]));
            } else {
                arrayList.add(zzqs.zze);
            }
        }
        ArrayList arrayList2 = new ArrayList();
        arrayList2.add(new zzqz("gtmUtils"));
        zzqx zzqxVar = new zzqx("15", arrayList2);
        ArrayList arrayList3 = new ArrayList();
        arrayList3.add(zzqxVar);
        arrayList3.add(new zzqz(DTBMetricsConfiguration.APSMETRICS_LEVEL2_KEY));
        zzqx zzqxVar2 = new zzqx("17", arrayList3);
        ArrayList arrayList4 = new ArrayList();
        arrayList4.add(zzqxVar2);
        arrayList4.add(new zzqz(zzjjVar.zza()));
        arrayList4.add(new zzqv(arrayList));
        return new zzqx("2", arrayList4);
    }

    public static String zzb(String str) {
        Map map = zzb;
        if (map.containsKey(str)) {
            return ((zzjj) map.get(str)).zza();
        }
        return null;
    }
}

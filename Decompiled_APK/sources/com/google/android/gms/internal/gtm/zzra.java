package com.google.android.gms.internal.gtm;

import android.os.Bundle;
import android.support.v4.media.session.a;
import com.google.android.gms.common.internal.u;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

/* loaded from: classes2.dex */
public abstract class zzra {
    public static Bundle zza(Map map) {
        if (map == null) {
            return null;
        }
        Bundle bundle = new Bundle(map.size());
        for (Map.Entry entry : map.entrySet()) {
            if (entry.getValue() instanceof zzqz) {
                bundle.putString((String) entry.getKey(), ((zzqz) entry.getValue()).zzk());
            } else if (entry.getValue() instanceof zzqp) {
                bundle.putBoolean((String) entry.getKey(), ((zzqp) entry.getValue()).zzi().booleanValue());
            } else if (entry.getValue() instanceof zzqq) {
                bundle.putDouble((String) entry.getKey(), ((zzqq) entry.getValue()).zzi().doubleValue());
            } else {
                if (!(entry.getValue() instanceof zzqw)) {
                    throw new IllegalArgumentException(String.format("Invalid param type for key '%s'. Only boolean, double and string types and maps of thereof are supported.", entry.getKey()));
                }
                bundle.putBundle((String) entry.getKey(), zza(((zzqw) entry.getValue()).zza));
            }
        }
        return bundle;
    }

    public static zzqo zzb(Object obj) {
        if (obj == null) {
            return zzqs.zzd;
        }
        if (obj instanceof zzqo) {
            return (zzqo) obj;
        }
        if (obj instanceof Boolean) {
            return new zzqp((Boolean) obj);
        }
        if (obj instanceof Short) {
            return new zzqq(Double.valueOf(((Short) obj).doubleValue()));
        }
        if (obj instanceof Integer) {
            return new zzqq(Double.valueOf(((Integer) obj).doubleValue()));
        }
        if (obj instanceof Long) {
            return new zzqq(Double.valueOf(((Long) obj).doubleValue()));
        }
        if (obj instanceof Float) {
            return new zzqq(Double.valueOf(((Float) obj).doubleValue()));
        }
        if (obj instanceof Double) {
            return new zzqq((Double) obj);
        }
        if (!(obj instanceof Byte) && !(obj instanceof Character)) {
            if (obj instanceof String) {
                return new zzqz((String) obj);
            }
            if (obj instanceof List) {
                ArrayList arrayList = new ArrayList();
                Iterator it2 = ((List) obj).iterator();
                while (it2.hasNext()) {
                    arrayList.add(zzb(it2.next()));
                }
                return new zzqv(arrayList);
            }
            if (obj instanceof Map) {
                HashMap map = new HashMap();
                for (Map.Entry entry : ((Map) obj).entrySet()) {
                    u.b(entry.getKey() instanceof String);
                    map.put((String) entry.getKey(), zzb(entry.getValue()));
                }
                return new zzqw(map);
            }
            if (!(obj instanceof Bundle)) {
                throw new UnsupportedOperationException("Type not supported: ".concat(String.valueOf(obj.getClass())));
            }
            HashMap map2 = new HashMap();
            Bundle bundle = (Bundle) obj;
            for (String str : bundle.keySet()) {
                map2.put(str, zzb(bundle.get(str)));
            }
            return new zzqw(map2);
        }
        return new zzqz(obj.toString());
    }

    public static zzqo zzc(zzhx zzhxVar, zzqo zzqoVar) {
        u.h(zzqoVar);
        if (!zzj(zzqoVar) && !(zzqoVar instanceof zzqr) && !(zzqoVar instanceof zzqv) && !(zzqoVar instanceof zzqw)) {
            if (!(zzqoVar instanceof zzqx)) {
                throw new UnsupportedOperationException("Attempting to evaluate unknown type");
            }
            zzqoVar = zzd(zzhxVar, (zzqx) zzqoVar);
        }
        if (zzqoVar == null) {
            throw new IllegalArgumentException("AbstractType evaluated to Java null");
        }
        if (zzqoVar instanceof zzqx) {
            throw new IllegalArgumentException("AbstractType evaluated to illegal type Statement.");
        }
        return zzqoVar;
    }

    public static zzqo zzd(zzhx zzhxVar, zzqx zzqxVar) {
        String strZzi = zzqxVar.zzi();
        List listZzj = zzqxVar.zzj();
        zzqo zzqoVarZzb = zzhxVar.zzb(strZzi);
        if (zzqoVarZzb == null) {
            throw new UnsupportedOperationException(a.B("Function '", strZzi, "' is not supported"));
        }
        if (zzqoVarZzb instanceof zzqr) {
            return ((zzqr) zzqoVarZzb).zzi().zzd(zzhxVar, (zzqo[]) listZzj.toArray(new zzqo[listZzj.size()]));
        }
        throw new UnsupportedOperationException(a.B("Function '", strZzi, "' is not a function"));
    }

    public static zzqo zze(zzqo zzqoVar) {
        if (zzqoVar instanceof zzqw) {
            HashSet hashSet = new HashSet();
            Map map = ((zzqw) zzqoVar).zza;
            for (Map.Entry entry : map.entrySet()) {
                if (entry.getValue() == zzqs.zze) {
                    hashSet.add((String) entry.getKey());
                }
            }
            Iterator it2 = hashSet.iterator();
            while (it2.hasNext()) {
                map.remove((String) it2.next());
            }
        }
        return zzqoVar;
    }

    public static zzqs zzf(zzhx zzhxVar, List list) {
        Iterator it2 = list.iterator();
        while (it2.hasNext()) {
            zzqo zzqoVar = (zzqo) it2.next();
            u.b(zzqoVar instanceof zzqx);
            zzqo zzqoVarZzc = zzc(zzhxVar, zzqoVar);
            if (zzi(zzqoVarZzc)) {
                return (zzqs) zzqoVarZzc;
            }
        }
        return zzqs.zze;
    }

    public static Object zzg(zzqo zzqoVar) {
        if (zzqoVar == null || zzqoVar == zzqs.zzd) {
            return null;
        }
        if (zzqoVar instanceof zzqp) {
            return ((zzqp) zzqoVar).zzi();
        }
        if (zzqoVar instanceof zzqq) {
            zzqq zzqqVar = (zzqq) zzqoVar;
            double dDoubleValue = zzqqVar.zzi().doubleValue();
            return (Double.isInfinite(dDoubleValue) || dDoubleValue - Math.floor(dDoubleValue) >= 1.0E-5d) ? zzqqVar.zzi().toString() : Integer.valueOf((int) dDoubleValue);
        }
        if (zzqoVar instanceof zzqz) {
            return ((zzqz) zzqoVar).zzk();
        }
        if (zzqoVar instanceof zzqv) {
            ArrayList arrayList = new ArrayList();
            for (zzqo zzqoVar2 : ((zzqv) zzqoVar).zzk()) {
                Object objZzg = zzg(zzqoVar2);
                if (objZzg == null) {
                    zzhi.zza(String.format("Failure to convert a list element to object: %s (%s)", zzqoVar2, zzqoVar2.getClass().getCanonicalName()));
                    return null;
                }
                arrayList.add(objZzg);
            }
            return arrayList;
        }
        if (!(zzqoVar instanceof zzqw)) {
            zzhi.zza("Converting to Object from unknown abstract type: ".concat(String.valueOf(zzqoVar.getClass())));
            return null;
        }
        HashMap map = new HashMap();
        for (Map.Entry entry : ((zzqw) zzqoVar).zza.entrySet()) {
            Object objZzg2 = zzg((zzqo) entry.getValue());
            if (objZzg2 == null) {
                zzhi.zza(String.format("Failure to convert a map's value to object: %s (%s)", entry.getValue(), ((zzqo) entry.getValue()).getClass().getCanonicalName()));
                return null;
            }
            map.put((String) entry.getKey(), objZzg2);
        }
        return map;
    }

    public static Map zzh(Bundle bundle) {
        HashMap map = new HashMap();
        for (String str : bundle.keySet()) {
            Object obj = bundle.get(str);
            if (obj instanceof Bundle) {
                map.put(str, zzh((Bundle) obj));
            } else if (obj instanceof List) {
                map.put(str, zzk((List) obj));
            } else {
                map.put(str, obj);
            }
        }
        return map;
    }

    public static boolean zzi(zzqo zzqoVar) {
        if (zzqoVar == zzqs.zzc || zzqoVar == zzqs.zzb) {
            return true;
        }
        return (zzqoVar instanceof zzqs) && ((zzqs) zzqoVar).zzj();
    }

    public static boolean zzj(zzqo zzqoVar) {
        return (zzqoVar instanceof zzqp) || (zzqoVar instanceof zzqq) || (zzqoVar instanceof zzqz) || zzqoVar == zzqs.zzd || zzqoVar == zzqs.zze;
    }

    private static List zzk(List list) {
        ArrayList arrayList = new ArrayList();
        for (Object obj : list) {
            if (obj instanceof Bundle) {
                arrayList.add(zzh((Bundle) obj));
            } else if (obj instanceof List) {
                arrayList.add(zzk((List) obj));
            } else {
                arrayList.add(obj);
            }
        }
        return arrayList;
    }
}

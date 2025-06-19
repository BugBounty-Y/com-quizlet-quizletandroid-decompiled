package com.google.android.gms.internal.gtm;

import com.google.android.gms.common.internal.u;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public abstract class zzoz {
    public static zzjl zza(Object obj) throws JSONException {
        String string;
        JSONArray jSONArray;
        JSONArray jSONArray2;
        if (obj instanceof JSONObject) {
            JSONObject jSONObject = (JSONObject) obj;
            string = jSONObject.getString("name");
            jSONArray2 = jSONObject.getJSONArray("params");
            jSONArray = jSONObject.getJSONArray("instructions");
        } else {
            if (!(obj instanceof JSONArray)) {
                throw new IllegalArgumentException("invalid JSON in runtime section");
            }
            JSONArray jSONArray3 = (JSONArray) obj;
            u.b(jSONArray3.length() >= 3);
            string = jSONArray3.getString(1);
            JSONArray jSONArray4 = jSONArray3.getJSONArray(2);
            JSONArray jSONArray5 = new JSONArray();
            for (int i = 1; i < jSONArray4.length(); i++) {
                u.b(jSONArray4.get(i) instanceof String);
                jSONArray5.put(jSONArray4.get(i));
            }
            JSONArray jSONArray6 = new JSONArray();
            for (int i2 = 3; i2 < jSONArray3.length(); i2++) {
                jSONArray6.put(jSONArray3.get(i2));
            }
            jSONArray = jSONArray6;
            jSONArray2 = jSONArray5;
        }
        ArrayList arrayList = new ArrayList();
        for (int i3 = 0; i3 < jSONArray2.length(); i3++) {
            arrayList.add(jSONArray2.getString(i3));
        }
        ArrayList arrayList2 = new ArrayList();
        for (int i4 = 0; i4 < jSONArray.length(); i4++) {
            JSONArray jSONArray7 = jSONArray.getJSONArray(i4);
            if (jSONArray7.length() != 0) {
                arrayList2.add(zze(jSONArray7));
            }
        }
        return new zzjl(null, string, arrayList, arrayList2);
    }

    public static zzqe zzb(JSONArray jSONArray, List list, List list2) throws JSONException, zzoy {
        zzqc zzqcVar = new zzqc();
        for (int i = 0; i < jSONArray.length(); i++) {
            JSONArray jSONArray2 = jSONArray.getJSONArray(i);
            int i2 = 1;
            if (jSONArray2.getString(0).equals("if")) {
                while (i2 < jSONArray2.length()) {
                    zzqcVar.zzc((zzqb) list2.get(jSONArray2.getInt(i2)));
                    i2++;
                }
            } else if (jSONArray2.getString(0).equals("unless")) {
                while (i2 < jSONArray2.length()) {
                    zzqcVar.zzb((zzqb) list2.get(jSONArray2.getInt(i2)));
                    i2++;
                }
            } else if (jSONArray2.getString(0).equals("add")) {
                while (i2 < jSONArray2.length()) {
                    zzqcVar.zza((zzqb) list.get(jSONArray2.getInt(i2)));
                    i2++;
                }
            } else if (jSONArray2.getString(0).equals("block")) {
                while (i2 < jSONArray2.length()) {
                    zzqcVar.zzd((zzqb) list.get(jSONArray2.getInt(i2)));
                    i2++;
                }
            } else {
                zzf("Unknown Rule property: ".concat(String.valueOf(jSONArray2.getString(0))));
            }
        }
        return zzqcVar.zze();
    }

    public static zzqi zzc(Object obj, List list) throws JSONException, zzoy {
        if (!(obj instanceof JSONArray)) {
            if (obj instanceof Boolean) {
                return new zzqi(8, obj);
            }
            if (obj instanceof Integer) {
                return new zzqi(6, obj);
            }
            if (obj instanceof String) {
                return new zzqi(1, obj);
            }
            zzf("Invalid value type: ".concat(String.valueOf(obj)));
            return null;
        }
        JSONArray jSONArray = (JSONArray) obj;
        String string = jSONArray.getString(0);
        if (string.equals("escape")) {
            zzqi zzqiVarZzc = zzc(jSONArray.get(1), list);
            for (int i = 2; i < jSONArray.length(); i++) {
                zzqiVarZzc.zza(jSONArray.getInt(i));
            }
            return zzqiVarZzc;
        }
        if (string.equals("list")) {
            ArrayList arrayList = new ArrayList();
            for (int i2 = 1; i2 < jSONArray.length(); i2++) {
                arrayList.add(zzc(jSONArray.get(i2), list).zzc());
            }
            zzqi zzqiVar = new zzqi(2, arrayList);
            zzqiVar.zzb(true);
            return zzqiVar;
        }
        if (string.equals("map")) {
            HashMap map = new HashMap();
            for (int i3 = 1; i3 < jSONArray.length(); i3 += 2) {
                map.put(zzc(jSONArray.get(i3), list).zzc(), zzc(jSONArray.get(i3 + 1), list).zzc());
            }
            zzqi zzqiVar2 = new zzqi(3, map);
            zzqiVar2.zzb(true);
            return zzqiVar2;
        }
        if (string.equals("macro")) {
            zzqi zzqiVar3 = new zzqi(4, list.get(jSONArray.getInt(1)));
            zzqiVar3.zzb(true);
            return zzqiVar3;
        }
        if (!string.equals("template")) {
            zzf("Invalid value type: ".concat(String.valueOf(obj)));
            return null;
        }
        ArrayList arrayList2 = new ArrayList();
        for (int i4 = 1; i4 < jSONArray.length(); i4++) {
            arrayList2.add(zzc(jSONArray.get(i4), list).zzc());
        }
        zzqi zzqiVar4 = new zzqi(7, arrayList2);
        zzqiVar4.zzb(true);
        return zzqiVar4;
    }

    public static List zzd(JSONArray jSONArray, List list) throws JSONException, zzoy {
        ArrayList arrayList = new ArrayList();
        for (int i = 0; i < jSONArray.length(); i++) {
            JSONObject jSONObject = jSONArray.getJSONObject(i);
            zzpz zzpzVar = new zzpz();
            Iterator<String> itKeys = jSONObject.keys();
            while (itKeys.hasNext()) {
                String next = itKeys.next();
                zzqk zzqkVarZzc = zzc(jSONObject.get(next), list).zzc();
                if ("push_after_evaluate".equals(next)) {
                    zzpzVar.zzb(zzqkVarZzc);
                } else {
                    zzpzVar.zza(next, zzqkVarZzc);
                }
            }
            arrayList.add(zzpzVar.zzc());
        }
        return arrayList;
    }

    private static zzqx zze(JSONArray jSONArray) throws JSONException {
        u.b(jSONArray.length() > 0);
        String string = jSONArray.getString(0);
        ArrayList arrayList = new ArrayList();
        for (int i = 1; i < jSONArray.length(); i++) {
            Object obj = jSONArray.get(i);
            if (obj instanceof JSONArray) {
                JSONArray jSONArray2 = (JSONArray) obj;
                if (jSONArray2.length() != 0) {
                    arrayList.add(zze(jSONArray2));
                }
            } else if (obj == JSONObject.NULL) {
                arrayList.add(zzqs.zzd);
            } else {
                arrayList.add(zzra.zzb(obj));
            }
        }
        return new zzqx(string, arrayList);
    }

    private static void zzf(String str) throws zzoy {
        zzhi.zza(str);
        throw new zzoy(str);
    }
}

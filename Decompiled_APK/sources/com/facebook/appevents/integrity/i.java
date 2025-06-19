package com.facebook.appevents.integrity;

import android.os.Bundle;
import com.facebook.internal.J;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Locale;
import java.util.Set;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.Regex;
import org.json.JSONArray;
import org.json.JSONObject;

/* loaded from: classes.dex */
public final class i {
    public static boolean b;
    public static final i a = new i();
    public static final HashMap c = new HashMap();
    public static final HashMap d = new HashMap();

    public static final void c(Bundle bundle) {
        if (com.facebook.internal.instrument.crashshield.a.b(i.class)) {
            return;
        }
        try {
            if (b && bundle != null) {
                ArrayList arrayList = new ArrayList();
                for (String key : bundle.keySet()) {
                    String strValueOf = String.valueOf(bundle.get(key));
                    HashMap map = c;
                    boolean z = false;
                    boolean z2 = map.get(key) != null;
                    HashMap map2 = d;
                    boolean z3 = map2.get(key) != null;
                    if (z2 || z3) {
                        i iVar = a;
                        Set set = (Set) map.get(key);
                        if (!com.facebook.internal.instrument.crashshield.a.b(iVar) && set != null) {
                            try {
                                Set set2 = set;
                                if (!(set2 instanceof Collection) || !set2.isEmpty()) {
                                    Iterator it2 = set2.iterator();
                                    while (true) {
                                        if (it2.hasNext()) {
                                            if (new Regex((String) it2.next()).e(strValueOf)) {
                                                z = true;
                                                break;
                                            }
                                        } else {
                                            break;
                                        }
                                    }
                                }
                            } catch (Throwable th) {
                                com.facebook.internal.instrument.crashshield.a.a(iVar, th);
                            }
                        }
                        boolean zB = iVar.b(strValueOf, (Set) map2.get(key));
                        if (!z && !zB) {
                            Intrinsics.checkNotNullExpressionValue(key, "key");
                            arrayList.add(key);
                        }
                    }
                }
                Iterator it3 = arrayList.iterator();
                while (it3.hasNext()) {
                    bundle.remove((String) it3.next());
                }
            }
        } catch (Throwable th2) {
            com.facebook.internal.instrument.crashshield.a.a(i.class, th2);
        }
    }

    public final void a(JSONArray jSONArray) {
        HashSet hashSet;
        HashMap map = c;
        HashMap map2 = d;
        if (com.facebook.internal.instrument.crashshield.a.b(this) || jSONArray == null) {
            return;
        }
        try {
            if (b) {
                return;
            }
            int length = jSONArray.length();
            for (int i = 0; i < length; i++) {
                JSONObject jSONObject = jSONArray.getJSONObject(i);
                String key = jSONObject.getString("key");
                if (key != null && key.length() != 0) {
                    try {
                        JSONArray jSONArray2 = jSONObject.getJSONArray("value");
                        int length2 = jSONArray2.length();
                        for (int i2 = 0; i2 < length2; i2++) {
                            boolean z = jSONArray2.getJSONObject(i2).getBoolean("require_exact_match");
                            JSONArray jSONArray3 = jSONArray2.getJSONObject(i2).getJSONArray("potential_matches");
                            HashSet hashSet2 = null;
                            if (!com.facebook.internal.instrument.crashshield.a.b(this)) {
                                try {
                                    try {
                                        hashSet = J.f(jSONArray3);
                                        if (hashSet == null) {
                                            hashSet = new HashSet();
                                        }
                                    } catch (Exception unused) {
                                        hashSet = new HashSet();
                                    }
                                    hashSet2 = hashSet;
                                } catch (Throwable th) {
                                    com.facebook.internal.instrument.crashshield.a.a(this, th);
                                }
                            }
                            if (z) {
                                Intrinsics.checkNotNullExpressionValue(key, "key");
                                HashSet hashSet3 = (HashSet) map2.get(key);
                                if (hashSet3 != null) {
                                    hashSet3.addAll(hashSet2);
                                    hashSet2 = hashSet3;
                                }
                                map2.put(key, hashSet2);
                            } else {
                                Intrinsics.checkNotNullExpressionValue(key, "key");
                                HashSet hashSet4 = (HashSet) map.get(key);
                                if (hashSet4 != null) {
                                    hashSet4.addAll(hashSet2);
                                    hashSet2 = hashSet4;
                                }
                                map.put(key, hashSet2);
                            }
                        }
                    } catch (Exception unused2) {
                        map2.remove(key);
                        map.remove(key);
                    }
                }
            }
        } catch (Throwable th2) {
            com.facebook.internal.instrument.crashshield.a.a(this, th2);
        }
    }

    public final boolean b(String str, Set set) {
        if (!com.facebook.internal.instrument.crashshield.a.b(this) && set != null) {
            try {
                Set<String> set2 = set;
                if (!(set2 instanceof Collection) || !set2.isEmpty()) {
                    for (String str2 : set2) {
                        Locale locale = Locale.ROOT;
                        String lowerCase = str2.toLowerCase(locale);
                        Intrinsics.checkNotNullExpressionValue(lowerCase, "this as java.lang.String).toLowerCase(Locale.ROOT)");
                        String lowerCase2 = str.toLowerCase(locale);
                        Intrinsics.checkNotNullExpressionValue(lowerCase2, "this as java.lang.String).toLowerCase(Locale.ROOT)");
                        if (Intrinsics.b(lowerCase, lowerCase2)) {
                            return true;
                        }
                    }
                }
            } catch (Throwable th) {
                com.facebook.internal.instrument.crashshield.a.a(this, th);
            }
        }
        return false;
    }
}

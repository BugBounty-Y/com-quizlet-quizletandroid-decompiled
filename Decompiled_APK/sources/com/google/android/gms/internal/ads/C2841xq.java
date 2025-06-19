package com.google.android.gms.internal.ads;

import android.location.Location;
import android.os.Bundle;
import com.amazon.device.ads.DtbDeviceData;
import com.google.android.gms.ads.internal.client.zzm;
import com.google.android.gms.ads.internal.client.zzx;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.TreeSet;

/* renamed from: com.google.android.gms.internal.ads.xq, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2841xq implements InterfaceC2798wq {
    public final Object[] a;

    public C2841xq(zzm zzmVar, String str, int i, String str2, zzx zzxVar) {
        HashSet hashSet = new HashSet(Arrays.asList(str2.split(",")));
        ArrayList arrayList = new ArrayList();
        arrayList.add(str2);
        arrayList.add(str);
        if (hashSet.contains("networkType")) {
            arrayList.add(Integer.valueOf(i));
        }
        if (hashSet.contains("birthday")) {
            arrayList.add(Long.valueOf(zzmVar.b));
        }
        if (hashSet.contains("extras")) {
            arrayList.add(a(zzmVar.c));
        } else if (hashSet.contains("npa")) {
            arrayList.add(zzmVar.c.getString("npa"));
        }
        if (hashSet.contains("gender")) {
            arrayList.add(Integer.valueOf(zzmVar.d));
        }
        if (hashSet.contains("keywords")) {
            List list = zzmVar.e;
            if (list != null) {
                arrayList.add(list.toString());
            } else {
                arrayList.add(null);
            }
        }
        if (hashSet.contains("isTestDevice")) {
            arrayList.add(Boolean.valueOf(zzmVar.f));
        }
        if (hashSet.contains("tagForChildDirectedTreatment")) {
            arrayList.add(Integer.valueOf(zzmVar.g));
        }
        if (hashSet.contains("manualImpressionsEnabled")) {
            arrayList.add(Boolean.valueOf(zzmVar.h));
        }
        if (hashSet.contains("publisherProvidedId")) {
            arrayList.add(zzmVar.i);
        }
        if (hashSet.contains("location")) {
            Location location = zzmVar.k;
            if (location != null) {
                arrayList.add(location.toString());
            } else {
                arrayList.add(null);
            }
        }
        if (hashSet.contains("contentUrl")) {
            arrayList.add(zzmVar.l);
        }
        if (hashSet.contains("networkExtras")) {
            arrayList.add(a(zzmVar.m));
        }
        if (hashSet.contains("customTargeting")) {
            arrayList.add(a(zzmVar.n));
        }
        if (hashSet.contains("categoryExclusions")) {
            List list2 = zzmVar.o;
            if (list2 != null) {
                arrayList.add(list2.toString());
            } else {
                arrayList.add(null);
            }
        }
        if (hashSet.contains("requestAgent")) {
            arrayList.add(zzmVar.p);
        }
        if (hashSet.contains("requestPackage")) {
            arrayList.add(zzmVar.q);
        }
        if (hashSet.contains("isDesignedForFamilies")) {
            arrayList.add(Boolean.valueOf(zzmVar.r));
        }
        if (hashSet.contains("tagForUnderAgeOfConsent")) {
            arrayList.add(Integer.valueOf(zzmVar.t));
        }
        if (hashSet.contains("maxAdContentRating")) {
            arrayList.add(zzmVar.u);
        }
        if (hashSet.contains(DtbDeviceData.DEVICE_DATA_ORIENTATION_KEY)) {
            if (zzxVar != null) {
                arrayList.add(Integer.valueOf(zzxVar.a));
            } else {
                arrayList.add(null);
            }
        }
        this.a = arrayList.toArray();
    }

    public static String a(Bundle bundle) {
        if (bundle == null) {
            return null;
        }
        StringBuilder sb = new StringBuilder();
        Iterator it2 = new TreeSet(bundle.keySet()).iterator();
        while (it2.hasNext()) {
            Object obj = bundle.get((String) it2.next());
            sb.append(obj == null ? "null" : obj instanceof Bundle ? a((Bundle) obj) : obj.toString());
        }
        return sb.toString();
    }

    public final boolean equals(Object obj) {
        if (obj instanceof C2841xq) {
            return Arrays.equals(this.a, ((C2841xq) obj).a);
        }
        return false;
    }

    public final int hashCode() {
        return Arrays.hashCode(this.a);
    }

    public final String toString() {
        Object[] objArr = this.a;
        return "[PoolKey#" + Arrays.hashCode(objArr) + " " + Arrays.toString(objArr) + "]";
    }
}

package com.google.android.gms.internal.gtm;

import java.util.Iterator;
import java.util.Set;

/* loaded from: classes2.dex */
public abstract class zzty {
    public static int zza(Set set) {
        Iterator it2 = set.iterator();
        int iHashCode = 0;
        while (it2.hasNext()) {
            Object next = it2.next();
            iHashCode += next != null ? next.hashCode() : 0;
        }
        return iHashCode;
    }
}

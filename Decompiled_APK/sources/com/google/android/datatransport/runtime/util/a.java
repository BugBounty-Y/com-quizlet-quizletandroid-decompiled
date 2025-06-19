package com.google.android.datatransport.runtime.util;

import android.util.SparseArray;
import com.google.android.datatransport.d;
import java.util.HashMap;

/* loaded from: classes2.dex */
public abstract class a {
    public static final SparseArray a = new SparseArray();
    public static final HashMap b;

    static {
        HashMap map = new HashMap();
        b = map;
        map.put(d.a, 0);
        map.put(d.b, 1);
        map.put(d.c, 2);
        for (d dVar : map.keySet()) {
            a.append(((Integer) b.get(dVar)).intValue(), dVar);
        }
    }

    public static int a(d dVar) {
        Integer num = (Integer) b.get(dVar);
        if (num != null) {
            return num.intValue();
        }
        throw new IllegalStateException("PriorityMapping is missing known Priority value " + dVar);
    }

    public static d b(int i) {
        d dVar = (d) a.get(i);
        if (dVar != null) {
            return dVar;
        }
        throw new IllegalArgumentException(android.support.v4.media.session.a.f(i, "Unknown Priority for value "));
    }
}

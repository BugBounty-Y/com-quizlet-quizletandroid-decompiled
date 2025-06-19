package com.snowplowanalytics.core.utils;

import com.snowplowanalytics.core.tracker.m;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.WeakHashMap;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public abstract class c {
    public static final HashMap a = new HashMap();
    public static final WeakHashMap b = new WeakHashMap();

    public static final synchronized void a(String notificationType, m observer) {
        try {
            Intrinsics.checkNotNullParameter(notificationType, "notificationType");
            Intrinsics.checkNotNullParameter(observer, "observer");
            b bVar = new b(observer);
            bVar.a = true;
            b bVar2 = (b) b.put(observer, bVar);
            if (bVar2 != null) {
                synchronized (bVar2) {
                    bVar2.a = false;
                    bVar2.clear();
                }
            }
            HashMap map = a;
            List linkedList = (List) map.get(notificationType);
            if (linkedList == null) {
                linkedList = new LinkedList();
                map.put(notificationType, linkedList);
            }
            linkedList.add(bVar);
        } catch (Throwable th) {
            throw th;
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    public static final synchronized void b(HashMap data, String notificationType) {
        boolean z;
        try {
            Intrinsics.checkNotNullParameter(notificationType, "notificationType");
            Intrinsics.checkNotNullParameter(data, "data");
            List list = (List) a.get(notificationType);
            if (list != null && !list.isEmpty()) {
                Iterator it2 = list.iterator();
                while (it2.hasNext()) {
                    b bVar = (b) it2.next();
                    synchronized (bVar) {
                        z = bVar.a && bVar.get() != 0;
                    }
                    if (z) {
                        HashMap map = new HashMap(data);
                        m mVar = (m) bVar.get();
                        if (mVar != null) {
                            mVar.a(map);
                        }
                    } else {
                        synchronized (c.class) {
                            it2.remove();
                            Unit unit = Unit.a;
                        }
                    }
                }
                list.isEmpty();
            }
        } finally {
        }
    }

    public static final synchronized void c(m observer) {
        Intrinsics.checkNotNullParameter(observer, "observer");
        b bVar = (b) b.remove(observer);
        if (bVar != null) {
            synchronized (bVar) {
                bVar.a = false;
                bVar.clear();
            }
        }
    }
}

package com.google.protobuf;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/* loaded from: classes2.dex */
public final class G extends I {
    public static final Class c = Collections.unmodifiableList(Collections.EMPTY_LIST).getClass();

    public static List d(long j, Object obj, int i) {
        List list = (List) t0.c.i(j, obj);
        if (list.isEmpty()) {
            List e = list instanceof F ? new E(i) : ((list instanceof Y) && (list instanceof B)) ? ((B) list).q(i) : new ArrayList(i);
            t0.p(j, obj, e);
            return e;
        }
        if (c.isAssignableFrom(list.getClass())) {
            ArrayList arrayList = new ArrayList(list.size() + i);
            arrayList.addAll(list);
            t0.p(j, obj, arrayList);
            return arrayList;
        }
        if (list instanceof o0) {
            E e2 = new E(list.size() + i);
            e2.addAll((o0) list);
            t0.p(j, obj, e2);
            return e2;
        }
        if ((list instanceof Y) && (list instanceof B)) {
            B b = (B) list;
            if (!((AbstractC4006b) b).a) {
                B bQ = b.q(list.size() + i);
                t0.p(j, obj, bQ);
                return bQ;
            }
        }
        return list;
    }

    @Override // com.google.protobuf.I
    public final void a(long j, Object obj) {
        Object objUnmodifiableList;
        List list = (List) t0.c.i(j, obj);
        if (list instanceof F) {
            objUnmodifiableList = ((F) list).D();
        } else {
            if (c.isAssignableFrom(list.getClass())) {
                return;
            }
            if ((list instanceof Y) && (list instanceof B)) {
                AbstractC4006b abstractC4006b = (AbstractC4006b) ((B) list);
                boolean z = abstractC4006b.a;
                if (z && z) {
                    abstractC4006b.a = false;
                    return;
                }
                return;
            }
            objUnmodifiableList = Collections.unmodifiableList(list);
        }
        t0.p(j, obj, objUnmodifiableList);
    }

    @Override // com.google.protobuf.I
    public final void b(long j, Object obj, Object obj2) {
        List list = (List) t0.c.i(j, obj2);
        List listD = d(j, obj, list.size());
        int size = listD.size();
        int size2 = list.size();
        if (size > 0 && size2 > 0) {
            listD.addAll(list);
        }
        if (size > 0) {
            list = listD;
        }
        t0.p(j, obj, list);
    }

    @Override // com.google.protobuf.I
    public final List c(long j, Object obj) {
        return d(j, obj, 10);
    }
}

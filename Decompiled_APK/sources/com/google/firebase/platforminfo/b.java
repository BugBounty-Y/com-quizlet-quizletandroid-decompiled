package com.google.firebase.platforminfo;

import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

/* loaded from: classes2.dex */
public final class b {
    public final String a;
    public final c b;

    public b(Set set, c cVar) {
        this.a = b(set);
        this.b = cVar;
    }

    public static String b(Set set) {
        StringBuilder sb = new StringBuilder();
        Iterator it2 = set.iterator();
        while (it2.hasNext()) {
            a aVar = (a) it2.next();
            sb.append(aVar.a);
            sb.append('/');
            sb.append(aVar.b);
            if (it2.hasNext()) {
                sb.append(' ');
            }
        }
        return sb.toString();
    }

    public final String a() {
        Set setUnmodifiableSet;
        Set setUnmodifiableSet2;
        c cVar = this.b;
        synchronized (((HashSet) cVar.a)) {
            setUnmodifiableSet = Collections.unmodifiableSet((HashSet) cVar.a);
        }
        boolean zIsEmpty = setUnmodifiableSet.isEmpty();
        String str = this.a;
        if (zIsEmpty) {
            return str;
        }
        StringBuilder sb = new StringBuilder();
        sb.append(str);
        sb.append(' ');
        synchronized (((HashSet) cVar.a)) {
            setUnmodifiableSet2 = Collections.unmodifiableSet((HashSet) cVar.a);
        }
        sb.append(b(setUnmodifiableSet2));
        return sb.toString();
    }
}

package com.squareup.moshi;

import java.lang.reflect.Type;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Set;

/* loaded from: classes3.dex */
public final class D {
    public static final ArrayList d;
    public final List a;
    public final ThreadLocal b = new ThreadLocal();
    public final LinkedHashMap c = new LinkedHashMap();

    static {
        ArrayList arrayList = new ArrayList(5);
        d = arrayList;
        arrayList.add(H.a);
        arrayList.add(C4852g.c);
        arrayList.add(C4846a.e);
        arrayList.add(C4846a.d);
        arrayList.add(E.a);
        arrayList.add(C4851f.d);
    }

    public D(com.google.firebase.crashlytics.internal.metadata.p pVar) {
        ArrayList arrayList = pVar.a;
        int size = arrayList.size();
        ArrayList arrayList2 = d;
        ArrayList arrayList3 = new ArrayList(arrayList2.size() + size);
        arrayList3.addAll(arrayList);
        arrayList3.addAll(arrayList2);
        this.a = Collections.unmodifiableList(arrayList3);
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r12v4, types: [com.squareup.moshi.l] */
    public final l a(Type type, Set set, String str) {
        B b;
        if (type == null) {
            throw new NullPointerException("type == null");
        }
        if (set == null) {
            throw new NullPointerException("annotations == null");
        }
        Type typeF = com.squareup.moshi.internal.b.f(com.squareup.moshi.internal.b.a(type));
        Object objAsList = set.isEmpty() ? typeF : Arrays.asList(typeF, set);
        synchronized (this.c) {
            try {
                l lVar = (l) this.c.get(objAsList);
                if (lVar != null) {
                    return lVar;
                }
                C c = (C) this.b.get();
                if (c == null) {
                    c = new C(this);
                    this.b.set(c);
                }
                ArrayList arrayList = c.a;
                int size = arrayList.size();
                int i = 0;
                while (true) {
                    ArrayDeque arrayDeque = c.b;
                    if (i >= size) {
                        B b2 = new B(typeF, str, objAsList);
                        arrayList.add(b2);
                        arrayDeque.add(b2);
                        b = null;
                        break;
                    }
                    b = (B) arrayList.get(i);
                    if (b.c.equals(objAsList)) {
                        arrayDeque.add(b);
                        ?? r12 = b.d;
                        if (r12 != 0) {
                            b = r12;
                        }
                    } else {
                        i++;
                    }
                }
                try {
                    if (b != null) {
                        return b;
                    }
                    try {
                        int size2 = this.a.size();
                        for (int i2 = 0; i2 < size2; i2++) {
                            l lVarA = ((k) this.a.get(i2)).a(typeF, set, this);
                            if (lVarA != null) {
                                ((B) c.b.getLast()).d = lVarA;
                                c.b(true);
                                return lVarA;
                            }
                        }
                        throw new IllegalArgumentException("No JsonAdapter for " + com.squareup.moshi.internal.b.i(typeF, set));
                    } catch (IllegalArgumentException e) {
                        throw c.a(e);
                    }
                } finally {
                    c.b(false);
                }
            } finally {
            }
        }
    }
}

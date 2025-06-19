package com.squareup.moshi;

import java.lang.reflect.InvocationTargetException;
import java.util.TreeMap;

/* renamed from: com.squareup.moshi.f, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4851f extends l {
    public static final com.quizlet.remote.model.selectedterm.c d = new com.quizlet.remote.model.selectedterm.c(2);
    public final H a;
    public final C4850e[] b;
    public final com.airbnb.lottie.parser.moshi.c c;

    public C4851f(H h, TreeMap treeMap) {
        this.a = h;
        this.b = (C4850e[]) treeMap.values().toArray(new C4850e[treeMap.size()]);
        this.c = com.airbnb.lottie.parser.moshi.c.b((String[]) treeMap.keySet().toArray(new String[treeMap.size()]));
    }

    @Override // com.squareup.moshi.l
    public final Object a(p pVar) throws IllegalAccessException, IllegalArgumentException {
        try {
            Object objE = this.a.e();
            try {
                pVar.d();
                while (pVar.l()) {
                    int iK0 = pVar.k0(this.c);
                    if (iK0 == -1) {
                        pVar.m0();
                        pVar.n0();
                    } else {
                        C4850e c4850e = this.b[iK0];
                        c4850e.b.set(objE, c4850e.c.a(pVar));
                    }
                }
                pVar.i();
                return objE;
            } catch (IllegalAccessException unused) {
                throw new AssertionError();
            }
        } catch (IllegalAccessException unused2) {
            throw new AssertionError();
        } catch (InstantiationException e) {
            throw new RuntimeException(e);
        } catch (InvocationTargetException e2) {
            com.squareup.moshi.internal.b.h(e2);
            throw null;
        }
    }

    @Override // com.squareup.moshi.l
    public final void g(w wVar, Object obj) throws IllegalAccessException, IllegalArgumentException {
        try {
            wVar.d();
            for (C4850e c4850e : this.b) {
                wVar.l(c4850e.a);
                c4850e.c.g(wVar, c4850e.b.get(obj));
            }
            wVar.f();
        } catch (IllegalAccessException unused) {
            throw new AssertionError();
        }
    }

    public final String toString() {
        return "JsonAdapter(" + this.a + ")";
    }
}

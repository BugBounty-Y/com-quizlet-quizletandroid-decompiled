package com.squareup.moshi;

import java.io.IOException;
import java.util.Map;
import okio.C5091h;

/* loaded from: classes3.dex */
public abstract class l {
    public abstract Object a(p pVar);

    public final Object b(String str) {
        C5091h c5091h = new C5091h();
        c5091h.u0(str);
        q qVar = new q(c5091h);
        Object objA = a(qVar);
        if (d() || qVar.Q() == o.j) {
            return objA;
        }
        throw new JsonDataException("JSON document was not fully consumed.");
    }

    public final Object c(Map map) {
        u uVar = new u();
        int[] iArr = uVar.b;
        int i = uVar.a;
        iArr[i] = 7;
        Object[] objArr = new Object[32];
        uVar.g = objArr;
        uVar.a = i + 1;
        objArr[i] = map;
        try {
            return a(uVar);
        } catch (IOException e) {
            throw new AssertionError(e);
        }
    }

    public boolean d() {
        return this instanceof j;
    }

    public final com.squareup.moshi.internal.a e() {
        return this instanceof com.squareup.moshi.internal.a ? (com.squareup.moshi.internal.a) this : new com.squareup.moshi.internal.a(this);
    }

    public final String f(Object obj) {
        C5091h c5091h = new C5091h();
        try {
            g(new s(c5091h), obj);
            return c5091h.U();
        } catch (IOException e) {
            throw new AssertionError(e);
        }
    }

    public abstract void g(w wVar, Object obj);
}

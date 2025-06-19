package com.squareup.moshi.internal;

import com.squareup.moshi.l;
import com.squareup.moshi.o;
import com.squareup.moshi.p;
import com.squareup.moshi.w;

/* loaded from: classes3.dex */
public final class a extends l {
    public final l a;

    public a(l lVar) {
        this.a = lVar;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p pVar) {
        if (pVar.Q() != o.i) {
            return this.a.a(pVar);
        }
        pVar.C();
        return null;
    }

    @Override // com.squareup.moshi.l
    public final void g(w wVar, Object obj) {
        if (obj == null) {
            wVar.p();
        } else {
            this.a.g(wVar, obj);
        }
    }

    public final String toString() {
        return this.a + ".nullSafe()";
    }
}

package com.squareup.moshi;

import java.lang.reflect.Type;

/* loaded from: classes3.dex */
public final class B extends l {
    public final Type a;
    public final String b;
    public final Object c;
    public l d;

    public B(Type type, String str, Object obj) {
        this.a = type;
        this.b = str;
        this.c = obj;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p pVar) {
        l lVar = this.d;
        if (lVar != null) {
            return lVar.a(pVar);
        }
        throw new IllegalStateException("JsonAdapter isn't ready");
    }

    @Override // com.squareup.moshi.l
    public final void g(w wVar, Object obj) {
        l lVar = this.d;
        if (lVar == null) {
            throw new IllegalStateException("JsonAdapter isn't ready");
        }
        lVar.g(wVar, obj);
    }

    public final String toString() {
        l lVar = this.d;
        return lVar != null ? lVar.toString() : super.toString();
    }
}

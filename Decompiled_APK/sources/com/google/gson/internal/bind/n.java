package com.google.gson.internal.bind;

import com.google.gson.q;
import com.google.gson.r;
import com.google.gson.reflect.TypeToken;

/* loaded from: classes2.dex */
public final class n implements r {
    public final /* synthetic */ Class a;
    public final /* synthetic */ Class b;
    public final /* synthetic */ q c;

    public n(Class cls, Class cls2, q qVar) {
        this.a = cls;
        this.b = cls2;
        this.c = qVar;
    }

    @Override // com.google.gson.r
    public final q b(com.google.gson.k kVar, TypeToken typeToken) {
        Class cls = this.a;
        Class cls2 = typeToken.a;
        if (cls2 == cls || cls2 == this.b) {
            return this.c;
        }
        return null;
    }

    public final String toString() {
        return "Factory[type=" + this.b.getName() + "+" + this.a.getName() + ",adapter=" + this.c + "]";
    }
}

package com.google.gson.internal.bind;

import com.google.gson.q;
import com.google.gson.r;
import com.google.gson.reflect.TypeToken;

/* loaded from: classes2.dex */
public final class k implements r {
    public final TypeToken a;
    public final boolean b;
    public final com.auth0.android.jwt.c c;

    public k(com.auth0.android.jwt.c cVar, TypeToken typeToken, boolean z) {
        this.c = cVar;
        this.a = typeToken;
        this.b = z;
    }

    @Override // com.google.gson.r
    public final q b(com.google.gson.k kVar, TypeToken typeToken) {
        TypeToken typeToken2 = this.a;
        if (typeToken2 == null) {
            throw null;
        }
        if (typeToken2.equals(typeToken) || (this.b && typeToken2.b == typeToken.a)) {
            return new l(this.c, kVar, typeToken, this);
        }
        return null;
    }
}

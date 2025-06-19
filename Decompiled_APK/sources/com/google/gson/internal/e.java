package com.google.gson.internal;

import com.google.gson.reflect.TypeToken;
import java.io.IOException;

/* loaded from: classes2.dex */
public final class e extends com.google.gson.q {
    public com.google.gson.q a;
    public final /* synthetic */ boolean b;
    public final /* synthetic */ com.google.gson.k c;
    public final /* synthetic */ TypeToken d;
    public final /* synthetic */ f e;

    public e(f fVar, boolean z, boolean z2, com.google.gson.k kVar, TypeToken typeToken) {
        this.e = fVar;
        this.b = z;
        this.c = kVar;
        this.d = typeToken;
    }

    @Override // com.google.gson.q
    public final Object a(com.google.gson.stream.a aVar) throws IOException {
        if (this.b) {
            aVar.q0();
            return null;
        }
        com.google.gson.q qVarC = this.a;
        if (qVarC == null) {
            qVarC = this.c.c(this.e, this.d);
            this.a = qVarC;
        }
        return qVarC.a(aVar);
    }
}

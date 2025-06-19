package com.squareup.moshi;

/* loaded from: classes3.dex */
public final class i extends l {
    public final /* synthetic */ l a;

    public i(l lVar) {
        this.a = lVar;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p pVar) {
        return this.a.a(pVar);
    }

    @Override // com.squareup.moshi.l
    public final boolean d() {
        return this.a.d();
    }

    @Override // com.squareup.moshi.l
    public final void g(w wVar, Object obj) {
        boolean z = wVar.e;
        wVar.e = true;
        try {
            this.a.g(wVar, obj);
        } finally {
            wVar.e = z;
        }
    }

    public final String toString() {
        return this.a + ".serializeNulls()";
    }
}

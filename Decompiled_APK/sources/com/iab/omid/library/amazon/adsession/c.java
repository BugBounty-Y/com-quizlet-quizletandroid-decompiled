package com.iab.omid.library.amazon.adsession;

import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3763y;

/* loaded from: classes2.dex */
public final class c {
    public final i a;
    public final i b;
    public final boolean c;
    public final f d;

    public c(f fVar, i iVar, i iVar2, boolean z) {
        this.d = fVar;
        this.a = iVar;
        if (iVar2 == null) {
            this.b = i.NONE;
        } else {
            this.b = iVar2;
        }
        this.c = z;
    }

    public static c a(f fVar, i iVar, i iVar2, boolean z) {
        AbstractC3763y.a(fVar, "CreativeType is null");
        AbstractC3763y.a(iVar, "Impression owner is null");
        if (iVar == i.NONE) {
            throw new IllegalArgumentException("Impression owner is none");
        }
        f fVar2 = f.DEFINED_BY_JAVASCRIPT;
        i iVar3 = i.NATIVE;
        if (fVar == fVar2 && iVar == iVar3) {
            throw new IllegalArgumentException("ImpressionType/CreativeType can only be defined as DEFINED_BY_JAVASCRIPT if Impression Owner is JavaScript");
        }
        return new c(fVar, iVar, iVar2, z);
    }
}

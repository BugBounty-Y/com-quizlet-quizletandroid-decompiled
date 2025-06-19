package com.google.common.cache;

/* loaded from: classes2.dex */
public enum w extends x {
    public w() {
        super("WEAK", 2);
    }

    @Override // com.google.common.cache.x
    public final com.google.common.base.f a() {
        return com.google.common.base.e.a;
    }

    @Override // com.google.common.cache.x
    public final C b(s sVar, J j, Object obj) {
        return new G(sVar.i, obj, j);
    }
}

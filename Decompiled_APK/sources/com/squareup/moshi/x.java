package com.squareup.moshi;

/* loaded from: classes3.dex */
public final class x extends com.google.gson.internal.k {
    public final /* synthetic */ int f;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ x(A a, int i) {
        super(a);
        this.f = i;
    }

    @Override // com.google.gson.internal.k, java.util.Iterator
    public Object next() {
        switch (this.f) {
            case 1:
                return b().f;
            default:
                return super.next();
        }
    }
}

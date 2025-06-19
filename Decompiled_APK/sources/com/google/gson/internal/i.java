package com.google.gson.internal;

/* loaded from: classes2.dex */
public final class i extends k {
    public final /* synthetic */ int f;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ i(m mVar, int i) {
        super(mVar);
        this.f = i;
    }

    @Override // com.google.gson.internal.k, java.util.Iterator
    public Object next() {
        switch (this.f) {
            case 1:
                return a().f;
            default:
                return super.next();
        }
    }
}

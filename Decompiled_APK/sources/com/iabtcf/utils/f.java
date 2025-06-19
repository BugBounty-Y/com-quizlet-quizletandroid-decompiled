package com.iabtcf.utils;

/* loaded from: classes2.dex */
public final class f implements g {
    public final /* synthetic */ int b;

    public f(int i) {
        this.b = i;
    }

    @Override // com.iabtcf.utils.g
    public final boolean a() {
        return false;
    }

    @Override // java.util.function.Function
    public final Object apply(Object obj) {
        return Integer.valueOf(this.b);
    }
}

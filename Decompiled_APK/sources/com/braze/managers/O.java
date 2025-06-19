package com.braze.managers;

import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final /* synthetic */ class O implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ com.braze.models.l b;

    public /* synthetic */ O(com.braze.models.l lVar, int i) {
        this.a = i;
        this.b = lVar;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return r.b(this.b);
            case 1:
                return r.c(this.b);
            case 2:
                return r.d(this.b);
            case 3:
                return r.e(this.b);
            default:
                return r.a(this.b);
        }
    }
}

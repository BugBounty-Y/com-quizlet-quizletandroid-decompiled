package com.braze.managers;

import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final /* synthetic */ class M implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ C1500m b;

    public /* synthetic */ M(C1500m c1500m, int i) {
        this.a = i;
        this.b = c1500m;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return C1500m.c(this.b);
            case 1:
                return C1500m.b(this.b);
            default:
                return C1500m.a(this.b);
        }
    }
}

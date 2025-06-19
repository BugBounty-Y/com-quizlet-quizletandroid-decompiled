package com.braze.dispatch;

import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final /* synthetic */ class i implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ f b;

    public /* synthetic */ i(f fVar, int i) {
        this.a = i;
        this.b = fVar;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return f.c(this.b);
            case 1:
                return f.a(this.b);
            case 2:
                return f.d(this.b);
            default:
                return f.b(this.b);
        }
    }
}

package com.braze;

import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final /* synthetic */ class z implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Class b;

    public /* synthetic */ z(Class cls, int i) {
        this.a = i;
        this.b = cls;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return Braze.removeSingleSubscription$lambda$129(this.b);
            case 1:
                return Braze.addSingleSynchronousSubscription$lambda$125(this.b);
            case 2:
                return com.braze.events.d.d(this.b);
            case 3:
                return com.braze.events.d.b(this.b);
            default:
                return com.braze.events.d.c(this.b);
        }
    }
}

package com.braze.triggers.actions;

import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final /* synthetic */ class i implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ c b;

    public /* synthetic */ i(c cVar, int i) {
        this.a = i;
        this.b = cVar;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return c.b(this.b);
            default:
                return c.a(this.b);
        }
    }
}

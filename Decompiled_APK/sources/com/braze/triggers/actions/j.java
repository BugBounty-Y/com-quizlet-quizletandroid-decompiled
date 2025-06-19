package com.braze.triggers.actions;

import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final /* synthetic */ class j implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ com.braze.triggers.events.b b;

    public /* synthetic */ j(com.braze.triggers.events.b bVar, int i) {
        this.a = i;
        this.b = bVar;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return c.c(this.b);
            case 1:
                return c.d(this.b);
            case 2:
                return com.braze.triggers.managers.f.b(this.b);
            case 3:
                return com.braze.triggers.managers.f.c(this.b);
            default:
                return com.braze.triggers.managers.f.e(this.b);
        }
    }
}

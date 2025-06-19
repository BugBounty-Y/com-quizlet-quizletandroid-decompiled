package com.braze.events;

import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final /* synthetic */ class g implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ com.braze.triggers.actions.a b;

    public /* synthetic */ g(com.braze.triggers.actions.a aVar, int i) {
        this.a = i;
        this.b = aVar;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return a.a(this.b);
            case 1:
                return com.braze.triggers.managers.a.a(this.b);
            case 2:
                return com.braze.triggers.managers.b.b(this.b);
            case 3:
                return com.braze.triggers.managers.b.c(this.b);
            case 4:
                return com.braze.triggers.managers.f.c(this.b);
            case 5:
                return com.braze.triggers.managers.f.d(this.b);
            case 6:
                return com.braze.triggers.managers.f.g(this.b);
            default:
                return com.braze.triggers.managers.f.f(this.b);
        }
    }
}

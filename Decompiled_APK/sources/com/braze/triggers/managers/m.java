package com.braze.triggers.managers;

import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final /* synthetic */ class m implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ com.braze.triggers.actions.g b;

    public /* synthetic */ m(com.braze.triggers.actions.g gVar, int i) {
        this.a = i;
        this.b = gVar;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return f.a(this.b);
            case 1:
                return g.a((com.braze.triggers.actions.a) this.b);
            case 2:
                return g.b(this.b);
            default:
                return g.c(this.b);
        }
    }
}

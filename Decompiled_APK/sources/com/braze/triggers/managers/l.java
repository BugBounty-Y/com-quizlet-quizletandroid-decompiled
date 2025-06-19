package com.braze.triggers.managers;

import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final /* synthetic */ class l implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ com.braze.triggers.actions.a b;
    public final /* synthetic */ long c;

    public /* synthetic */ l(com.braze.triggers.actions.a aVar, long j, int i) {
        this.a = i;
        this.b = aVar;
        this.c = j;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return f.a(this.b, this.c);
            default:
                return g.b(this.b, this.c);
        }
    }
}

package com.braze.requests.framework;

import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final /* synthetic */ class p implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ g b;
    public final /* synthetic */ long c;

    public /* synthetic */ p(g gVar, long j, int i) {
        this.a = i;
        this.b = gVar;
        this.c = j;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return g.b(this.b, this.c);
            default:
                return g.a(this.b, this.c);
        }
    }
}

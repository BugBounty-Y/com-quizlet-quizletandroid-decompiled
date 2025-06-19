package com.braze.models.response;

import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final /* synthetic */ class o implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ g b;

    public /* synthetic */ o(g gVar, int i) {
        this.a = i;
        this.b = gVar;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return g.a(this.b);
            case 1:
                return g.b(this.b);
            default:
                return com.braze.requests.framework.f.b(this.b);
        }
    }
}

package com.braze.requests;

import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final /* synthetic */ class A implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ com.braze.models.response.d b;

    public /* synthetic */ A(com.braze.models.response.d dVar, int i) {
        this.a = i;
        this.b = dVar;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return d.b(this.b);
            case 1:
                return v.a(this.b);
            default:
                return w.a(this.b);
        }
    }
}

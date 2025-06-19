package com.braze.managers;

import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final /* synthetic */ class T implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ com.braze.events.internal.o b;

    public /* synthetic */ T(com.braze.events.internal.o oVar, int i) {
        this.a = i;
        this.b = oVar;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return y.a(this.b);
            default:
                return com.braze.requests.framework.g.a(this.b);
        }
    }
}

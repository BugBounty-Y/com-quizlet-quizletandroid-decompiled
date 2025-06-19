package com.braze.communication;

import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final /* synthetic */ class h implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ com.braze.requests.util.c b;

    public /* synthetic */ h(com.braze.requests.util.c cVar, int i) {
        this.a = i;
        this.b = cVar;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return b.a(this.b);
            default:
                return com.braze.requests.d.a(this.b);
        }
    }
}

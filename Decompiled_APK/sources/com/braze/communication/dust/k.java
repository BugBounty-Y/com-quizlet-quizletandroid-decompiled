package com.braze.communication.dust;

import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final /* synthetic */ class k implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ h b;

    public /* synthetic */ k(h hVar, int i) {
        this.a = i;
        this.b = hVar;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return h.c(this.b);
            case 1:
                return h.d(this.b);
            case 2:
                return h.a(this.b);
            default:
                return h.b(this.b);
        }
    }
}

package com.braze.requests;

import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final /* synthetic */ class k implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ b b;

    public /* synthetic */ k(b bVar, int i) {
        this.a = i;
        this.b = bVar;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return b.c(this.b);
            case 1:
                return b.b(this.b);
            default:
                return b.a(this.b);
        }
    }
}

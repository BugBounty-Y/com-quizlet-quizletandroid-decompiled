package com.braze.storage;

import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final /* synthetic */ class A implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ AbstractC1515b b;

    public /* synthetic */ A(AbstractC1515b abstractC1515b, int i) {
        this.a = i;
        this.b = abstractC1515b;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return AbstractC1515b.a(this.b);
            default:
                return AbstractC1515b.b(this.b);
        }
    }
}

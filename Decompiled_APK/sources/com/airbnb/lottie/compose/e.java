package com.airbnb.lottie.compose;

import kotlin.jvm.functions.Function1;

/* loaded from: classes.dex */
public final class e extends kotlin.jvm.internal.r implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ h b;
    public final /* synthetic */ int c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ e(h hVar, int i, int i2) {
        super(1);
        this.a = i2;
        this.b = hVar;
        this.c = i;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                return Boolean.valueOf(h.a(this.b, this.c, ((Number) obj).longValue()));
            default:
                return Boolean.valueOf(h.a(this.b, this.c, ((Number) obj).longValue()));
        }
    }
}

package com.ionspin.kotlin.bignum.integer;

import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.r;

/* loaded from: classes2.dex */
public final class b extends r implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ c b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ b(c cVar, int i) {
        super(1);
        this.a = i;
        this.b = cVar;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                c it2 = (c) obj;
                Intrinsics.checkNotNullParameter(it2, "it");
                return Integer.valueOf(this.b.a(it2));
            default:
                c it3 = (c) obj;
                Intrinsics.checkNotNullParameter(it3, "it");
                return Integer.valueOf(this.b.a(it3));
        }
    }
}

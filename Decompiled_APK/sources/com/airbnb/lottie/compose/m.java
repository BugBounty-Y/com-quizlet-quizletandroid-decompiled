package com.airbnb.lottie.compose;

import androidx.compose.runtime.L0;
import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final class m extends kotlin.jvm.internal.r implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ n b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ m(n nVar, int i) {
        super(0);
        this.a = i;
        this.b = nVar;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                n nVar = this.b;
                return Boolean.valueOf((((com.airbnb.lottie.h) ((L0) nVar.b).getValue()) == null && ((Throwable) ((L0) nVar.c).getValue()) == null) ? false : true);
            case 1:
                return Boolean.valueOf(((Throwable) ((L0) this.b.c).getValue()) != null);
            case 2:
                n nVar2 = this.b;
                return Boolean.valueOf(((com.airbnb.lottie.h) ((L0) nVar2.b).getValue()) == null && ((Throwable) ((L0) nVar2.c).getValue()) == null);
            default:
                return Boolean.valueOf(((com.airbnb.lottie.h) ((L0) this.b.b).getValue()) != null);
        }
    }
}

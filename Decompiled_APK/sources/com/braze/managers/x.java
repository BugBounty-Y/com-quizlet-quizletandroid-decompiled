package com.braze.managers;

import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.C4956o;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final /* synthetic */ class x extends C4956o implements Function1 {
    public x(y yVar) {
        super(1, 0, y.class, yVar, "ingestDustMessages", "ingestDustMessages(Lcom/braze/models/dust/IDustMessage;)V");
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        com.braze.models.dust.e p0 = (com.braze.models.dust.e) obj;
        Intrinsics.checkNotNullParameter(p0, "p0");
        ((y) this.receiver).a(p0);
        return Unit.a;
    }
}

package com.quizlet.features.practicetest.common.composables;

import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.r;

/* loaded from: classes3.dex */
public final class j extends r implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ kotlinx.collections.immutable.e b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ j(kotlinx.collections.immutable.e eVar, int i) {
        super(1);
        this.a = i;
        this.b = eVar;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                this.b.get(((Number) obj).intValue());
                break;
            case 1:
                this.b.get(((Number) obj).intValue());
                break;
            default:
                this.b.get(((Number) obj).intValue());
                break;
        }
        return null;
    }
}

package com.quizlet.shared.di;

import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.r;

/* loaded from: classes3.dex */
public final class d extends r implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ com.quizlet.shared.cache.b b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ d(com.quizlet.shared.cache.b bVar, int i) {
        super(2);
        this.a = i;
        this.b = bVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                org.koin.core.scope.a single = (org.koin.core.scope.a) obj;
                org.koin.core.parameter.a it2 = (org.koin.core.parameter.a) obj2;
                Intrinsics.checkNotNullParameter(single, "$this$single");
                Intrinsics.checkNotNullParameter(it2, "it");
                return this.b.a;
            default:
                org.koin.core.scope.a single2 = (org.koin.core.scope.a) obj;
                org.koin.core.parameter.a it3 = (org.koin.core.parameter.a) obj2;
                Intrinsics.checkNotNullParameter(single2, "$this$single");
                Intrinsics.checkNotNullParameter(it3, "it");
                return this.b.b;
        }
    }
}

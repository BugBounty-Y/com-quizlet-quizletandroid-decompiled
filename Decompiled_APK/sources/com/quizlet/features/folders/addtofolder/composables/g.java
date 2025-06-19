package com.quizlet.features.folders.addtofolder.composables;

import kotlin.jvm.functions.Function1;

/* loaded from: classes3.dex */
public final class g extends kotlin.jvm.internal.r implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ kotlinx.collections.immutable.b b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ g(kotlinx.collections.immutable.b bVar, int i) {
        super(1);
        this.a = i;
        this.b = bVar;
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

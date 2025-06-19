package com.quizlet.features.emailconfirmation.ui.composables;

import kotlin.Unit;
import kotlin.jvm.functions.Function1;

/* loaded from: classes2.dex */
public final class m extends kotlin.jvm.internal.r implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ androidx.constraintlayout.compose.j b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ m(androidx.constraintlayout.compose.j jVar, int i) {
        super(1);
        this.a = i;
        this.b = jVar;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                kotlin.reflect.n nVar = androidx.constraintlayout.compose.l.a[0];
                androidx.constraintlayout.compose.l.b.a((androidx.compose.ui.semantics.v) obj, this.b);
                break;
            case 1:
                kotlin.reflect.n nVar2 = androidx.constraintlayout.compose.l.a[0];
                androidx.constraintlayout.compose.l.b.a((androidx.compose.ui.semantics.v) obj, this.b);
                break;
            case 2:
                kotlin.reflect.n nVar3 = androidx.constraintlayout.compose.l.a[0];
                androidx.constraintlayout.compose.l.b.a((androidx.compose.ui.semantics.v) obj, this.b);
                break;
            default:
                kotlin.reflect.n nVar4 = androidx.constraintlayout.compose.l.a[0];
                androidx.constraintlayout.compose.l.b.a((androidx.compose.ui.semantics.v) obj, this.b);
                break;
        }
        return Unit.a;
    }
}

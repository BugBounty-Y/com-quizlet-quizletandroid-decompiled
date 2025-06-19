package com.quizlet.features.practicetest.detail.viewmodel;

import com.quizlet.features.practicetest.detail.data.C4404g;
import com.quizlet.features.practicetest.detail.data.v;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;

/* loaded from: classes3.dex */
public final class g implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ i b;

    public /* synthetic */ g(i iVar, int i) {
        this.a = i;
        this.b = iVar;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                this.b.C(C4404g.a);
                break;
            case 1:
                i iVar = this.b;
                iVar.k.h(new v(iVar.m));
                break;
            case 2:
                this.b.C(C4404g.a);
                break;
            default:
                this.b.C(C4404g.a);
                break;
        }
        return Unit.a;
    }
}

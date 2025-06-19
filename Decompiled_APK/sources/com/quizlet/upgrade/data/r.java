package com.quizlet.upgrade.data;

import com.quizlet.quizletandroid.R;
import kotlin.Unit;
import kotlin.collections.C4933y;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final /* synthetic */ class r implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ s b;

    public /* synthetic */ r(s sVar, int i) {
        this.a = i;
        this.b = sVar;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                Object[] args = new Object[0];
                Intrinsics.checkNotNullParameter(args, "args");
                com.quizlet.qutils.string.f fVar = new com.quizlet.qutils.string.f(R.string.product_class_progress, C4933y.P(args));
                s sVar = this.b;
                com.quizlet.uicommon.ui.common.text.c cVar = new com.quizlet.uicommon.ui.common.text.c(fVar, new r(sVar, 1));
                Object[] args2 = new Object[0];
                Intrinsics.checkNotNullParameter(args2, "args");
                com.quizlet.uicommon.ui.common.text.c cVar2 = new com.quizlet.uicommon.ui.common.text.c(new com.quizlet.qutils.string.f(R.string.product_quizlet_live, C4933y.P(args2)), new r(sVar, 2));
                Object[] args3 = new Object[0];
                Intrinsics.checkNotNullParameter(args3, "args");
                break;
            case 1:
                this.b.b.invoke(F.b);
                break;
            default:
                this.b.b.invoke(F.c);
                break;
        }
        return Unit.a;
    }
}

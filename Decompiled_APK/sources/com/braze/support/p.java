package com.braze.support;

import androidx.lifecycle.X;
import com.quizlet.upgrade.data.C4833a;
import com.quizlet.upgrade.data.C4834b;
import com.quizlet.upgrade.ui.confirmation.UpgradeConfirmationFragment;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final /* synthetic */ class p implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ int b;
    public final /* synthetic */ Object c;

    public /* synthetic */ p(int i, Object obj, int i2) {
        this.a = i2;
        this.b = i;
        this.c = obj;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                break;
            case 1:
                break;
            case 2:
                break;
            case 3:
                break;
            case 4:
                ((com.quizlet.features.setpage.header.ui.g) this.c).invoke(Integer.valueOf(this.b));
                break;
            default:
                com.quizlet.upgrade.ui.confirmation.c cVar = (com.quizlet.upgrade.ui.confirmation.c) ((UpgradeConfirmationFragment) this.c).k.getValue();
                boolean z = cVar.c;
                X x = cVar.b;
                if (z) {
                    x.j(C4833a.a);
                } else if (cVar.d) {
                    x.j(new com.quizlet.upgrade.data.o(Integer.valueOf(this.b)));
                } else {
                    x.j(C4834b.a);
                }
                break;
        }
        return Unit.a;
    }

    public /* synthetic */ p(Object obj, int i, int i2) {
        this.a = i2;
        this.c = obj;
        this.b = i;
    }
}

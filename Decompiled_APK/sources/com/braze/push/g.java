package com.braze.push;

import com.google.firebase.messaging.p;
import com.quizlet.eventlogger.EventLogger;
import com.quizlet.eventlogger.EventLoggerExt;
import com.quizlet.features.setpage.r;
import com.quizlet.features.setpage.viewmodel.P;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final /* synthetic */ class g implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ boolean b;
    public final /* synthetic */ Object c;

    public /* synthetic */ g(boolean z, int i, Object obj) {
        this.a = i;
        this.c = obj;
        this.b = z;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                break;
            case 1:
                break;
            case 2:
                p pVar = ((r) this.c).R().f;
                pVar.getClass();
                EventLoggerExt.c((EventLogger) pVar.b, new com.quizlet.assembly.compose.modals.g(this.b, 5));
                break;
            default:
                P p = (P) this.c;
                p.i1.l((p.u1 || this.b) ? com.quizlet.features.infra.basestudy.data.models.e.a : com.quizlet.features.infra.basestudy.data.models.g.a);
                break;
        }
        return Unit.a;
    }
}

package com.quizlet.quizletandroid.ui.base;

import com.google.android.gms.internal.measurement.C3008j0;
import com.google.android.gms.internal.measurement.W;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final /* synthetic */ class c implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ g b;

    public /* synthetic */ c(g gVar, int i) {
        this.a = i;
        this.b = gVar;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                com.quizlet.data.connectivity.b bVar = (com.quizlet.data.connectivity.b) obj;
                Intrinsics.checkNotNullParameter(bVar, "<destruct>");
                boolean z = bVar.a;
                g gVar = this.b;
                boolean z2 = bVar.c;
                if (z && !z2) {
                    gVar.t.j(Unit.a);
                    gVar.e.h(true);
                    timber.log.c.a.m("Recording a connectivity change -> ON", new Object[0]);
                } else if (!z && z2) {
                    gVar.e.h(false);
                    timber.log.c.a.m("Recording a connectivity change -> OFF", new Object[0]);
                }
                break;
            default:
                Long userId = (Long) obj;
                Intrinsics.checkNotNullParameter(userId, "userId");
                String strValueOf = userId.longValue() == 0 ? null : String.valueOf(userId.longValue());
                C3008j0 c3008j0 = this.b.f.a;
                c3008j0.getClass();
                c3008j0.c(new W(c3008j0, strValueOf, 0));
                break;
        }
        return Unit.a;
    }
}

package com.quizlet.features.setpage;

import android.content.Intent;
import com.quizlet.features.setpage.viewmodel.C;
import com.quizlet.features.setpage.viewmodel.P;
import com.quizlet.quizletandroid.ui.diagramming.DiagramOverviewActivity;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.flow.InterfaceC5002j;

/* loaded from: classes3.dex */
public final class m implements InterfaceC5002j {
    public final /* synthetic */ int a;
    public final /* synthetic */ r b;

    public /* synthetic */ m(r rVar, int i) {
        this.a = i;
        this.b = rVar;
    }

    @Override // kotlinx.coroutines.flow.InterfaceC5002j
    public final Object emit(Object obj, kotlin.coroutines.h hVar) {
        r context = this.b;
        switch (this.a) {
            case 0:
                if (!(((com.quizlet.features.setpage.studypreview.d) obj) instanceof com.quizlet.features.setpage.studypreview.d)) {
                    throw new NoWhenBranchMatchedException();
                }
                String str = r.c1;
                P pR = context.R();
                pR.getClass();
                pR.H(new C(pR, null));
                return Unit.a;
            default:
                com.quizlet.features.setpage.termlist.data.l lVar = (com.quizlet.features.setpage.termlist.data.l) obj;
                if (!(lVar instanceof com.quizlet.features.setpage.termlist.data.l)) {
                    throw new NoWhenBranchMatchedException();
                }
                context.P();
                long j = lVar.a;
                Intrinsics.checkNotNullParameter(context, "activity");
                int i = DiagramOverviewActivity.o1;
                Intrinsics.checkNotNullParameter(context, "context");
                Intrinsics.checkNotNullParameter(context, "context");
                Intent intent = new Intent(context, (Class<?>) DiagramOverviewActivity.class);
                intent.putExtra("setId", j);
                context.startActivity(intent);
                return Unit.a;
        }
    }
}

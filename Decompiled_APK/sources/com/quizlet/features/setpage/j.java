package com.quizlet.features.setpage;

import android.os.Bundle;
import androidx.fragment.app.m0;
import com.quizlet.data.model.C4127f1;
import com.quizlet.db.data.models.persisted.DBStudySet;
import com.quizlet.eventlogger.EventLoggerExt;
import com.quizlet.features.setpage.viewmodel.C4430d;
import com.quizlet.features.setpage.viewmodel.J;
import com.quizlet.features.setpage.viewmodel.P;
import com.quizlet.generated.enums.G1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final /* synthetic */ class j implements m0, com.quizlet.uicommon.ui.common.dialogs.f {
    public final /* synthetic */ int a;
    public final /* synthetic */ r b;

    public /* synthetic */ j(r rVar, int i) {
        this.a = i;
        this.b = rVar;
    }

    @Override // com.quizlet.uicommon.ui.common.dialogs.f
    public void c(com.quizlet.uicommon.ui.common.dialogs.e eVar, int i) {
        switch (this.a) {
            case 1:
                com.quizlet.features.setpage.progress.presentation.viewmodel.a aVar = (com.quizlet.features.setpage.progress.presentation.viewmodel.a) this.b.H.getValue();
                EventLoggerExt.c(aVar.d.a, new com.quizlet.features.practicetest.navigation.a(19));
                com.quizlet.data.repository.set.f fVar = aVar.e;
                fVar.getClass();
                io.reactivex.rxjava3.subjects.r stopToken = aVar.c;
                Intrinsics.checkNotNullParameter(stopToken, "stopToken");
                io.reactivex.rxjava3.internal.operators.completable.a aVarA = ((androidx.work.impl.model.c) fVar.c).a(stopToken, new com.braze.triggers.managers.h(27, fVar, new C4127f1(aVar.f, aVar.i, G1.SET, Long.valueOf(System.currentTimeMillis() / 1000))));
                com.quizlet.eventlogger.e eVar2 = new com.quizlet.eventlogger.e(aVar, 8);
                com.quizlet.infra.legacysyncengine.net.request.g gVar = io.reactivex.rxjava3.internal.functions.d.d;
                io.reactivex.rxjava3.disposables.b bVarE = new io.reactivex.rxjava3.internal.operators.completable.i(aVarA, gVar, gVar, eVar2, io.reactivex.rxjava3.internal.functions.d.c).e();
                Intrinsics.checkNotNullExpressionValue(bVarE, "subscribe(...)");
                Intrinsics.checkNotNullParameter(bVarE, "<this>");
                aVar.A(bVarE);
                eVar.dismiss();
                return;
            case 2:
                EventLoggerExt.c(((com.quizlet.features.setpage.progress.presentation.viewmodel.a) this.b.H.getValue()).d.a, new com.quizlet.features.practicetest.navigation.a(17));
                eVar.dismiss();
                return;
            case 3:
                this.b.finish();
                return;
            default:
                r rVar = this.b;
                P pR = rVar.R();
                boolean zIsTaskRoot = rVar.isTaskRoot();
                if (pR.G()) {
                    pR.d1.j(com.quizlet.features.setpage.screenstates.q.a);
                    DBStudySet dBStudySet = pR.F1;
                    if (dBStudySet == null) {
                        Intrinsics.m("set");
                        throw null;
                    }
                    long id = dBStudySet.getId();
                    androidx.work.impl.model.c cVar = pR.n;
                    cVar.getClass();
                    timber.log.a aVar2 = timber.log.c.a;
                    aVar2.g("Removing app shortcut with ID: %s", Long.valueOf(id));
                    cVar.x(id);
                    DBStudySet dBStudySet2 = pR.F1;
                    if (dBStudySet2 == null) {
                        Intrinsics.m("set");
                        throw null;
                    }
                    dBStudySet2.setDeleted(true);
                    com.braze.push.g gVar2 = new com.braze.push.g(zIsTaskRoot, 3, pR);
                    DBStudySet dBStudySet3 = pR.F1;
                    if (dBStudySet3 == null) {
                        Intrinsics.m("set");
                        throw null;
                    }
                    io.reactivex.rxjava3.disposables.b bVarU = pR.j.a(dBStudySet3).i(new C4430d(0, pR, gVar2)).u(J.a, new com.quizlet.billing.manager.d(aVar2, 4), io.reactivex.rxjava3.internal.functions.d.c);
                    Intrinsics.checkNotNullExpressionValue(bVarU, "subscribe(...)");
                    Intrinsics.checkNotNullParameter(bVarU, "<this>");
                    pR.A(bVarU);
                }
                eVar.dismiss();
                return;
        }
    }

    @Override // androidx.fragment.app.m0
    public void y(Bundle result, String str) {
        Intrinsics.checkNotNullParameter(str, "<unused var>");
        Intrinsics.checkNotNullParameter(result, "result");
        if (result.getInt("resultCode") == -1) {
            r rVar = this.b;
            rVar.R().A1 = true;
            rVar.recreate();
        }
    }
}

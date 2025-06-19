package com.quizlet.infra.legacysyncengine.net.sync;

import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import com.google.android.gms.common.api.internal.k;
import com.quizlet.db.data.models.base.DBModel;
import com.quizlet.db.data.models.persisted.DBAnswer;
import com.quizlet.db.data.net.tasks.ExecutionRouter;
import io.reactivex.rxjava3.functions.h;
import io.reactivex.rxjava3.internal.functions.d;
import io.reactivex.rxjava3.internal.operators.observable.C4891j;
import io.reactivex.rxjava3.internal.operators.observable.U;
import timber.log.c;

/* loaded from: classes3.dex */
public final /* synthetic */ class a implements h {
    public final /* synthetic */ int a;
    public final /* synthetic */ k b;

    public /* synthetic */ a(k kVar, int i) {
        this.a = i;
        this.b = kVar;
    }

    @Override // io.reactivex.rxjava3.functions.h
    public final Object apply(Object obj) {
        switch (this.a) {
            case 0:
                DBModel dBModel = (DBModel) obj;
                k kVar = this.b;
                kVar.getClass();
                boolean zHasServerIdentity = dBModel.getIdentity().hasServerIdentity();
                boolean deleted = dBModel.getDeleted();
                com.quizlet.infra.legacysyncengine.net.constants.a aVar = com.quizlet.infra.legacysyncengine.net.constants.a.a;
                if (deleted) {
                    return zHasServerIdentity ? com.quizlet.infra.legacysyncengine.net.constants.a.d : aVar;
                }
                if (!zHasServerIdentity || !(dBModel instanceof DBAnswer)) {
                    return (!kVar.c || zHasServerIdentity) ? com.quizlet.infra.legacysyncengine.net.constants.a.c : aVar;
                }
                DBAnswer dBAnswer = (DBAnswer) dBModel;
                c.a.f(new UnsupportedOperationException("[ANDROID-4590] Server cannot update DBAnswer objects"), "Aborted update to DBAnswer { id = %s, setId = %s, sessionId = %s, termId = %s }", Long.valueOf(dBAnswer.getId()), Long.valueOf(dBAnswer.getSetId()), Long.valueOf(dBAnswer.getSessionId()), Long.valueOf(dBAnswer.getTermId()));
                return aVar;
            default:
                U u = (U) obj;
                k kVar2 = this.b;
                u.getClass();
                int i = kVar2.b;
                d.a(i, "count");
                d.a(i, "skip");
                return new io.reactivex.rxjava3.internal.operators.maybe.h(0, new C4891j(u, i, i).l(new com.quizlet.infra.legacysyncengine.models.serializers.a(6)).s(((ExecutionRouter) kVar2.e).b()).m(new com.google.firebase.tracing.a(18, kVar2, u), SubsamplingScaleImageView.TILE_SIZE_AUTO).x(16), new com.quizlet.infra.legacysyncengine.models.serializers.a(7)).g().q(new com.quizlet.infra.legacysyncengine.models.serializers.a(4));
        }
    }
}

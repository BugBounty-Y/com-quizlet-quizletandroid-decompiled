package com.quizlet.offline.managers;

import androidx.compose.animation.d0;
import androidx.compose.foundation.gestures.l1;
import com.google.android.datatransport.cct.internal.s;
import com.quizlet.db.data.models.persisted.base.Models;
import com.quizlet.db.data.models.persisted.fields.DBStudySetFields;
import com.quizlet.infra.legacysyncengine.models.identity.QueryIdFieldChangeMapper;
import io.reactivex.rxjava3.core.o;
import io.reactivex.rxjava3.core.p;
import io.reactivex.rxjava3.internal.operators.maybe.t;
import io.reactivex.rxjava3.internal.operators.maybe.w;
import io.reactivex.rxjava3.internal.operators.single.k;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class g implements io.reactivex.rxjava3.functions.h {
    public final /* synthetic */ int a;
    public final /* synthetic */ i b;
    public final /* synthetic */ long c;

    public /* synthetic */ g(i iVar, long j, int i) {
        this.a = i;
        this.b = iVar;
        this.c = j;
    }

    @Override // io.reactivex.rxjava3.functions.h
    public final Object apply(Object obj) {
        switch (this.a) {
            case 0:
                Long userId = (Long) obj;
                Intrinsics.checkNotNullParameter(userId, "userId");
                s sVar = this.b.f;
                com.quizlet.infra.legacysyncengine.orm.b bVar = new com.quizlet.infra.legacysyncengine.orm.b(Models.STUDY_SET);
                bVar.b(Long.valueOf(this.c), DBStudySetFields.ID);
                com.quizlet.infra.legacysyncengine.orm.query.a aVarA = bVar.a();
                com.quizlet.qutils.data.offline.d payload = new com.quizlet.qutils.data.offline.d(aVarA, com.quizlet.qutils.data.offline.c.a, true, com.quizlet.qutils.data.offline.b.c, com.quizlet.qutils.data.offline.a.d);
                long jLongValue = userId.longValue();
                Intrinsics.checkNotNullParameter(payload, "payload");
                if (jLongValue <= 0) {
                    timber.log.c.a.d(d0.o(jLongValue, "Invalid userID (", "), why are we checking if it's available?"), new Object[0]);
                    io.reactivex.rxjava3.internal.operators.flowable.b bVarF = p.f(Boolean.FALSE);
                    Intrinsics.checkNotNullExpressionValue(bVarF, "just(...)");
                    return bVarF;
                }
                k kVarF = ((s) sVar.e).h(((QueryIdFieldChangeMapper) sVar.d).convertStaleLocalIds(aVarA)).f();
                Intrinsics.checkNotNullExpressionValue(kVarF, "single(...)");
                Intrinsics.checkNotNullParameter(kVarF, "<this>");
                io.reactivex.rxjava3.internal.operators.maybe.h hVar = new io.reactivex.rxjava3.internal.operators.maybe.h(3, kVarF, com.quizlet.qutils.rx.a.b);
                Intrinsics.checkNotNullExpressionValue(hVar, "flatMapMaybe(...)");
                w wVar = new w(0, new t(new io.reactivex.rxjava3.internal.operators.maybe.j(new io.reactivex.rxjava3.internal.operators.maybe.j(new io.reactivex.rxjava3.internal.operators.maybe.j(new io.reactivex.rxjava3.internal.operators.maybe.j(hVar, new l1(payload, jLongValue, 23), 1), new com.quizlet.login.authentication.login.a(sVar, 4), 0), new com.quizlet.quizletandroid.data.management.f(sVar, 1), 0), com.quizlet.quizletandroid.data.management.c.e, 1)), Boolean.FALSE);
                Intrinsics.checkNotNullExpressionValue(wVar, "defaultIfEmpty(...)");
                return wVar;
            default:
                Long userId2 = (Long) obj;
                Intrinsics.checkNotNullParameter(userId2, "userId");
                s sVar2 = this.b.f;
                userId2.getClass();
                io.reactivex.rxjava3.internal.operators.completable.h hVarH = new io.reactivex.rxjava3.internal.operators.completable.c(new com.quizlet.data.repository.folderwithcreatorinclass.b(this.c, sVar2), 2).h((o) sVar2.i);
                Intrinsics.checkNotNullExpressionValue(hVarH, "subscribeOn(...)");
                return hVarH;
        }
    }
}

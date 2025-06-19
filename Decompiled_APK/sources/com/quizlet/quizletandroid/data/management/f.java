package com.quizlet.quizletandroid.data.management;

import androidx.compose.foundation.text.input.internal.u;
import com.google.android.datatransport.cct.internal.s;
import com.quizlet.db.data.models.persisted.base.Models;
import com.quizlet.db.data.models.persisted.fields.DBImageRefFields;
import com.quizlet.infra.legacysyncengine.models.identity.QueryIdFieldChangeMapper;
import io.reactivex.rxjava3.functions.h;
import io.reactivex.rxjava3.internal.operators.maybe.j;
import io.reactivex.rxjava3.internal.operators.maybe.l;
import io.reactivex.rxjava3.internal.operators.single.k;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final /* synthetic */ class f implements h {
    public final /* synthetic */ int a;
    public final /* synthetic */ s b;

    public /* synthetic */ f(s sVar, int i) {
        this.a = i;
        this.b = sVar;
    }

    @Override // io.reactivex.rxjava3.functions.h
    public final Object apply(Object obj) {
        switch (this.a) {
            case 0:
                a p0 = (a) obj;
                Intrinsics.checkNotNullParameter(p0, "p0");
                s sVar = this.b;
                io.reactivex.rxjava3.internal.operators.maybe.h hVar = new io.reactivex.rxjava3.internal.operators.maybe.h(3, sVar.f(p0), new com.quizlet.data.repository.explanations.myexplanations.a(sVar, false, p0, 25));
                Intrinsics.checkNotNullExpressionValue(hVar, "flatMapMaybe(...)");
                return hVar;
            default:
                a p02 = (a) obj;
                Intrinsics.checkNotNullParameter(p02, "p0");
                s sVar2 = this.b;
                if (!p02.a.getHasDiagrams()) {
                    l lVarC = io.reactivex.rxjava3.core.g.c(p02);
                    Intrinsics.checkNotNullExpressionValue(lVarC, "just(...)");
                    return lVarC;
                }
                com.quizlet.infra.legacysyncengine.orm.b bVar = new com.quizlet.infra.legacysyncengine.orm.b(Models.IMAGE_REF);
                bVar.b(Long.valueOf(p02.a.getId()), DBImageRefFields.MODEL_ID);
                com.quizlet.infra.legacysyncengine.orm.query.a aVarA = bVar.a();
                Intrinsics.checkNotNullExpressionValue(aVarA, "build(...)");
                k kVarF = ((s) sVar2.e).h(((QueryIdFieldChangeMapper) sVar2.d).convertStaleLocalIds(aVarA)).f();
                Intrinsics.checkNotNullExpressionValue(kVarF, "single(...)");
                Intrinsics.checkNotNullParameter(kVarF, "<this>");
                io.reactivex.rxjava3.internal.operators.maybe.h hVar2 = new io.reactivex.rxjava3.internal.operators.maybe.h(3, kVarF, com.quizlet.qutils.rx.a.b);
                Intrinsics.checkNotNullExpressionValue(hVar2, "flatMapMaybe(...)");
                j jVar = new j(new j(new j(new j(new j(hVar2, c.h, 0), new com.quizlet.data.repository.widget.b(sVar2, false, p02, 25), 0), new u(p02, false, sVar2, 24), 0), c.i, 0), new com.quizlet.quizletandroid.k(p02, 2), 1);
                Intrinsics.checkNotNullExpressionValue(jVar, "map(...)");
                return jVar;
        }
    }
}

package com.quizlet.quizletandroid.data.management;

import com.google.android.datatransport.cct.internal.s;
import com.quizlet.db.data.models.base.ModelField;
import com.quizlet.db.data.models.persisted.DBSession;
import com.quizlet.db.data.models.persisted.base.Models;
import com.quizlet.db.data.models.persisted.fields.DBSessionFields;
import com.quizlet.generated.enums.G1;
import io.reactivex.rxjava3.core.i;
import io.reactivex.rxjava3.functions.h;
import io.reactivex.rxjava3.internal.operators.observable.J;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class e implements h {
    public final /* synthetic */ int a;
    public final /* synthetic */ s b;

    public /* synthetic */ e(s sVar, int i) {
        this.a = i;
        this.b = sVar;
    }

    @Override // io.reactivex.rxjava3.functions.h
    public final Object apply(Object obj) {
        switch (this.a) {
            case 0:
                a info = (a) obj;
                Intrinsics.checkNotNullParameter(info, "info");
                com.quizlet.infra.legacysyncengine.orm.b bVar = new com.quizlet.infra.legacysyncengine.orm.b(Models.SESSION);
                bVar.b(Long.valueOf(info.c), DBSessionFields.PERSON);
                ModelField<DBSession, Long> modelField = DBSessionFields.ITEM_TYPE;
                G1 g1 = G1.SET;
                bVar.b(Long.valueOf(g1.b()), modelField);
                bVar.d(DBSessionFields.STUDYABLE, Long.valueOf(info.a.getId()), Long.valueOf(g1.b()));
                com.quizlet.infra.legacysyncengine.orm.query.a aVarA = bVar.a();
                Intrinsics.checkNotNullExpressionValue(aVarA, "build(...)");
                return this.b.o(aVarA);
            default:
                List p0 = (List) obj;
                Intrinsics.checkNotNullParameter(p0, "p0");
                s sVar = this.b;
                sVar.getClass();
                io.reactivex.rxjava3.internal.operators.single.g gVarG = new J(i.o(p0), new e(sVar, 0), 1).x(16).g(new com.quizlet.login.authentication.login.a(p0, 3));
                Intrinsics.checkNotNullExpressionValue(gVarG, "map(...)");
                return gVarG;
        }
    }
}

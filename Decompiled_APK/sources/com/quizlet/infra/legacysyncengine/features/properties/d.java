package com.quizlet.infra.legacysyncengine.features.properties;

import com.google.android.gms.measurement.internal.Z;
import com.quizlet.db.data.models.persisted.DBStudySet;
import com.quizlet.db.data.models.persisted.base.Models;
import com.quizlet.db.data.models.persisted.fields.DBStudySetFields;
import io.reactivex.rxjava3.core.p;
import io.reactivex.rxjava3.internal.operators.observable.C4887f;
import io.reactivex.rxjava3.subjects.r;
import kotlin.jvm.internal.Intrinsics;
import kotlin.l;
import kotlin.u;

/* loaded from: classes3.dex */
public final class d {
    public final com.quizlet.infra.legacysyncengine.net.c a;
    public final com.google.firebase.crashlytics.internal.settings.b b;
    public p c;
    public Long d;
    public final u e;
    public p f;

    public d(com.quizlet.infra.legacysyncengine.net.c loader, com.google.firebase.crashlytics.internal.settings.b studySetAdsDataProvider) {
        Intrinsics.checkNotNullParameter(loader, "loader");
        Intrinsics.checkNotNullParameter(studySetAdsDataProvider, "studySetAdsDataProvider");
        this.a = loader;
        this.b = studySetAdsDataProvider;
        this.e = l.b(new com.quizlet.featuregate.growthbook.a(this, 20));
        this.f = Z.f("create(...)");
    }

    public static void c(d dVar, long j) {
        r stopToken = new r();
        dVar.getClass();
        Intrinsics.checkNotNullParameter(stopToken, "stopToken");
        DBStudySet dBStudySet = new DBStudySet();
        dBStudySet.setId(j);
        dVar.b(dBStudySet, stopToken);
    }

    public final p a() {
        p pVar = this.c;
        if (pVar != null) {
            return pVar;
        }
        throw new IllegalArgumentException("Must call initialize first.");
    }

    public final void b(DBStudySet set, p stopToken) {
        p pVarF;
        Intrinsics.checkNotNullParameter(set, "set");
        Intrinsics.checkNotNullParameter(stopToken, "stopToken");
        Long l = this.d;
        long setId = set.getSetId();
        if (l != null && l.longValue() == setId) {
            return;
        }
        this.d = Long.valueOf(set.getSetId());
        if (set.getCreator() == null) {
            long id = set.getId();
            com.quizlet.infra.legacysyncengine.orm.b bVar = new com.quizlet.infra.legacysyncengine.orm.b(Models.STUDY_SET);
            bVar.e(DBStudySetFields.CREATOR);
            bVar.b(Long.valueOf(id), DBStudySetFields.ID);
            io.reactivex.rxjava3.internal.operators.flowable.b bVar2 = new io.reactivex.rxjava3.internal.operators.flowable.b(new C4887f(new com.jakewharton.rxbinding4.a(new a(this, bVar.a(), 1), 3).l(c.i).q(c.j), 5), 2);
            Intrinsics.checkNotNullExpressionValue(bVar2, "singleOrError(...)");
            pVarF = new io.reactivex.rxjava3.internal.operators.single.b(bVar2);
        } else {
            pVarF = p.f(set);
        }
        this.c = pVarF;
        this.f = stopToken;
    }
}

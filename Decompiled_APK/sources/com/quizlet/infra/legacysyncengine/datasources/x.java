package com.quizlet.infra.legacysyncengine.datasources;

import com.google.android.gms.internal.mlkit_vision_common.AbstractC3508o4;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3525r4;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3537t4;
import com.quizlet.db.data.models.persisted.base.Models;
import com.quizlet.db.data.models.persisted.fields.DBGroupSetFields;
import com.quizlet.db.data.models.persisted.fields.DBStudySetFields;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;

/* loaded from: classes3.dex */
public final /* synthetic */ class x implements io.reactivex.rxjava3.functions.h {
    public final /* synthetic */ int a;
    public final /* synthetic */ p b;

    public /* synthetic */ x(p pVar, int i) {
        this.a = i;
        this.b = pVar;
    }

    @Override // io.reactivex.rxjava3.functions.h
    public final Object apply(Object obj) {
        switch (this.a) {
            case 0:
                p pVar = this.b;
                pVar.getClass();
                HashSet hashSet = new HashSet(AbstractC3525r4.e(new ArrayList(AbstractC3508o4.a((List) obj, new g(2))), new com.quizlet.baserecyclerview.decoration.a(25)));
                com.quizlet.infra.legacysyncengine.orm.b bVar = new com.quizlet.infra.legacysyncengine.orm.b(Models.GROUP_SET);
                bVar.c(DBGroupSetFields.GROUP, hashSet, null);
                bVar.e(DBGroupSetFields.SET, DBStudySetFields.CREATOR);
                o oVar = new o(pVar.c, bVar.a());
                oVar.d();
                return oVar.f();
            case 1:
                p pVar2 = this.b;
                pVar2.getClass();
                com.quizlet.infra.legacysyncengine.orm.b bVar2 = new com.quizlet.infra.legacysyncengine.orm.b(Models.GROUP_SET);
                bVar2.c(DBGroupSetFields.GROUP, (HashSet) obj, null);
                bVar2.e(DBGroupSetFields.SET, DBStudySetFields.CREATOR);
                o oVar2 = new o(pVar2.c, bVar2.a());
                oVar2.d();
                return oVar2.f();
            default:
                p pVar3 = this.b;
                pVar3.getClass();
                com.quizlet.infra.legacysyncengine.orm.b bVar3 = new com.quizlet.infra.legacysyncengine.orm.b(Models.STUDY_SET);
                bVar3.c(DBStudySetFields.ID, (HashSet) obj, null);
                return pVar3.c.c(bVar3.a(), AbstractC3537t4.g(com.quizlet.infra.legacysyncengine.net.b.a));
        }
    }
}

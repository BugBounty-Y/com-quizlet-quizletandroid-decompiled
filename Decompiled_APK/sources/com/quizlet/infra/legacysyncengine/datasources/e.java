package com.quizlet.infra.legacysyncengine.datasources;

import com.google.android.gms.internal.mlkit_vision_common.AbstractC3508o4;
import com.quizlet.db.data.models.persisted.base.Models;
import com.quizlet.db.data.models.persisted.fields.DBStudySetFields;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;

/* loaded from: classes3.dex */
public final /* synthetic */ class e implements io.reactivex.rxjava3.functions.h {
    public final /* synthetic */ int a;
    public final /* synthetic */ h b;

    public /* synthetic */ e(h hVar, int i) {
        this.a = i;
        this.b = hVar;
    }

    @Override // io.reactivex.rxjava3.functions.h
    public final Object apply(Object obj) {
        switch (this.a) {
            case 0:
                h hVar = this.b;
                hVar.getClass();
                com.quizlet.infra.legacysyncengine.orm.b bVar = new com.quizlet.infra.legacysyncengine.orm.b(Models.STUDY_SET);
                bVar.c(DBStudySetFields.ID, (HashSet) obj, null);
                return hVar.c.c(bVar.a(), com.quizlet.infra.legacysyncengine.net.c.e);
            default:
                this.b.getClass();
                return new HashSet(new ArrayList(AbstractC3508o4.a((List) obj, new g(0))));
        }
    }
}

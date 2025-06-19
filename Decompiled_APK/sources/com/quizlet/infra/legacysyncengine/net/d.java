package com.quizlet.infra.legacysyncengine.net;

import com.quizlet.db.data.models.persisted.DBStudySet;
import com.quizlet.db.data.models.persisted.base.ModelType;
import com.quizlet.db.data.orm.Relationship;
import io.reactivex.rxjava3.functions.h;

/* loaded from: classes3.dex */
public final /* synthetic */ class d implements h {
    public final /* synthetic */ int a;
    public final /* synthetic */ f b;

    public /* synthetic */ d(f fVar, int i) {
        this.a = i;
        this.b = fVar;
    }

    @Override // io.reactivex.rxjava3.functions.h
    public final Object apply(Object obj) {
        switch (this.a) {
            case 0:
                return this.b.c((ModelType) obj);
            case 1:
                f fVar = this.b;
                fVar.getClass();
                return fVar.c(((Relationship) obj).getFromModelType());
            default:
                return this.b.a((DBStudySet) obj);
        }
    }
}

package com.quizlet.infra.legacysyncengine.tasks.parse;

import com.quizlet.api.model.ModelError;
import com.quizlet.db.data.models.base.DBModel;
import com.quizlet.db.data.models.persisted.base.ModelType;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/* loaded from: classes3.dex */
public final /* synthetic */ class c implements io.reactivex.rxjava3.functions.h, io.reactivex.rxjava3.functions.b {
    public final /* synthetic */ f a;
    public final /* synthetic */ ModelType b;
    public final /* synthetic */ List c;

    public /* synthetic */ c(f fVar, ModelType modelType, List list) {
        this.a = fVar;
        this.b = modelType;
        this.c = list;
    }

    @Override // io.reactivex.rxjava3.functions.b
    public Object apply(Object obj, Object obj2) {
        Map map = (Map) obj;
        e eVar = (e) obj2;
        this.a.getClass();
        ModelType modelType = this.b;
        List arrayList = (List) map.get(modelType);
        if (arrayList == null) {
            arrayList = new ArrayList();
            map.put(modelType, arrayList);
        }
        DBModel dBModelB = f.b(this.c, eVar);
        dBModelB.setDirty(false);
        ModelError modelError = eVar.d;
        if (modelError != null && (modelError.getCode().intValue() == 404 || eVar.d.getCode().intValue() == 403)) {
            dBModelB.setDeleted(true);
        }
        arrayList.add(dBModelB);
        return map;
    }

    @Override // io.reactivex.rxjava3.functions.h
    public Object apply(Object obj) {
        List list;
        List list2;
        e eVar = (e) obj;
        this.a.getClass();
        if (eVar.b == this.b && (list = this.c) != null) {
            int size = list.size();
            int i = eVar.a;
            if (size > i && (list2 = eVar.c) != null && list2.size() == 1) {
                ((DBModel) list2.get(0)).setLocalId(((DBModel) list.get(i)).getLocalId());
            }
        }
        return eVar;
    }
}

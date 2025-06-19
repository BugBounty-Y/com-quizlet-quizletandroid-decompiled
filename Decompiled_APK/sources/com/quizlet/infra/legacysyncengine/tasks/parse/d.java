package com.quizlet.infra.legacysyncengine.tasks.parse;

import com.quizlet.db.data.models.base.DBModel;
import com.quizlet.db.data.models.identity.ModelIdentityProvider;
import com.quizlet.db.data.models.persisted.base.ModelType;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

/* loaded from: classes3.dex */
public final /* synthetic */ class d implements io.reactivex.rxjava3.functions.b, io.reactivex.rxjava3.functions.h {
    public final /* synthetic */ f a;

    public /* synthetic */ d(f fVar) {
        this.a = fVar;
    }

    @Override // io.reactivex.rxjava3.functions.b
    public Object apply(Object obj, Object obj2) {
        HashMap map = (HashMap) obj;
        e eVar = (e) obj2;
        this.a.getClass();
        List list = eVar.c;
        if (list == null || eVar.d != null || eVar.e != null) {
            return map;
        }
        ModelType modelType = eVar.b;
        List arrayList = (List) map.get(modelType);
        if (arrayList == null) {
            arrayList = new ArrayList();
            map.put(modelType, arrayList);
        }
        arrayList.addAll(list);
        return map;
    }

    @Override // io.reactivex.rxjava3.functions.h
    public Object apply(Object obj) {
        HashMap map = (HashMap) obj;
        f fVar = this.a;
        fVar.getClass();
        HashMap map2 = new HashMap();
        for (Map.Entry entry : map.entrySet()) {
            if (!((ModelType) entry.getKey()).hasMultipleFieldIdentity()) {
                map2.put((ModelType) entry.getKey(), ModelIdentityProvider.singleFieldIdentityMap((List) entry.getValue()));
            }
        }
        Iterator it2 = map.entrySet().iterator();
        while (it2.hasNext()) {
            Iterator it3 = ((List) ((Map.Entry) it2.next()).getValue()).iterator();
            while (it3.hasNext()) {
                fVar.a.resolveRelations(map2, (DBModel) it3.next());
            }
        }
        return map;
    }
}

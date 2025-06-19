package com.quizlet.infra.legacysyncengine.net.importer;

import com.google.android.datatransport.cct.internal.s;
import com.j256.ormlite.dao.Dao;
import com.j256.ormlite.stmt.QueryBuilder;
import com.quizlet.db.data.database.DatabaseHelper;
import com.quizlet.db.data.models.identity.ModelIdentityCollection;
import com.quizlet.db.data.models.identity.ModelIdentityProvider;
import com.quizlet.db.data.models.persisted.base.ModelType;
import com.quizlet.db.data.net.tasks.ExecutionRouter;
import com.quizlet.infra.legacysyncengine.tasks.parse.h;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;

/* loaded from: classes3.dex */
public final /* synthetic */ class b implements Callable {
    public final /* synthetic */ int a;
    public final /* synthetic */ s b;
    public final /* synthetic */ HashMap c;

    public /* synthetic */ b(s sVar, HashMap map, int i) {
        this.a = i;
        this.b = sVar;
        this.c = map;
    }

    @Override // java.util.concurrent.Callable
    public final Object call() throws SQLException {
        switch (this.a) {
            case 0:
                s sVar = this.b;
                h hVar = (h) sVar.g;
                Iterator it2 = hVar.a().iterator();
                while (it2.hasNext()) {
                    ModelType modelType = (ModelType) it2.next();
                    if (!com.quizlet.infra.legacysyncengine.net.constants.a.b.equals((com.quizlet.infra.legacysyncengine.net.constants.a) sVar.h)) {
                        List list = (List) hVar.a.get(modelType);
                        List list2 = (List) ((Map) sVar.a).get(modelType);
                        if (list2 != null) {
                            ((ModelIdentityProvider) sVar.d).updateCachedModelWithServerIdInDatabase(list, list2);
                        }
                    }
                    HashMap map = this.c;
                    if (map.get(modelType) != null) {
                        ((DatabaseHelper) sVar.c).q((List) map.get(modelType));
                    }
                }
                break;
            default:
                s sVar2 = this.b;
                sVar2.getClass();
                HashMap map2 = this.c;
                for (ModelType modelType2 : map2.keySet()) {
                    Dao daoJ = ((DatabaseHelper) sVar2.c).j(modelType2);
                    ModelIdentityCollection modelIdentityCollection = (ModelIdentityCollection) map2.get(modelType2);
                    QueryBuilder queryBuilder = daoJ.queryBuilder();
                    modelIdentityCollection.whereIn(queryBuilder.where());
                    List listQuery = queryBuilder.query();
                    if (listQuery.size() > 0) {
                        ArrayList arrayList = new ArrayList();
                        Map map3 = (Map) sVar2.a;
                        map3.putIfAbsent(modelType2, arrayList);
                        ((List) map3.get(modelType2)).addAll(listQuery);
                    }
                }
                ((ExecutionRouter) sVar2.b).d(new a(sVar2, 1));
                break;
        }
        return null;
    }
}

package com.quizlet.infra.legacysyncengine.net.request;

import androidx.camera.camera2.internal.j0;
import androidx.compose.foundation.text.input.internal.u;
import com.google.android.datatransport.cct.internal.s;
import com.quizlet.api.model.ApiThreeWrapper;
import com.quizlet.db.data.database.DatabaseHelper;
import com.quizlet.db.data.models.base.DBModel;
import com.quizlet.db.data.models.identity.ModelIdentityProvider;
import com.quizlet.db.data.models.persisted.base.ModelType;
import com.quizlet.db.data.net.tasks.ExecutionRouter;
import io.reactivex.rxjava3.subjects.r;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

/* loaded from: classes3.dex */
public final /* synthetic */ class a implements io.reactivex.rxjava3.functions.h {
    public final /* synthetic */ int a;
    public final /* synthetic */ b b;

    public /* synthetic */ a(b bVar, int i) {
        this.a = i;
        this.b = bVar;
    }

    @Override // io.reactivex.rxjava3.functions.h
    public final Object apply(Object obj) {
        switch (this.a) {
            case 0:
                com.quizlet.infra.legacysyncengine.tasks.parse.h hVar = (com.quizlet.infra.legacysyncengine.tasks.parse.h) obj;
                b bVar = this.b;
                bVar.h = hVar;
                HashMap map = bVar.g;
                com.quizlet.infra.legacysyncengine.net.constants.a aVarB = bVar.b();
                s sVar = (s) bVar.d;
                com.quizlet.infra.legacysyncengine.net.listeners.d dVar = (com.quizlet.infra.legacysyncengine.net.listeners.d) sVar.d;
                u uVar = (u) sVar.f;
                ExecutionRouter executionRouter = (ExecutionRouter) sVar.e;
                s sVar2 = new s(executionRouter, (DatabaseHelper) sVar.b, (ModelIdentityProvider) sVar.c, dVar, uVar, hVar, map, aVarB);
                executionRouter.d(new com.quizlet.infra.legacysyncengine.net.importer.a(sVar2, 0));
                return (r) sVar2.i;
            case 1:
                Map map2 = (Map) obj;
                b bVar2 = this.b;
                bVar2.getClass();
                HashMap map3 = new HashMap();
                for (ModelType modelType : map2.keySet()) {
                    HashSet hashSet = new HashSet();
                    if (map2.get(modelType) != null) {
                        Iterator it2 = ((List) map2.get(modelType)).iterator();
                        while (it2.hasNext()) {
                            hashSet.add(((DBModel) it2.next()).getIdentity());
                        }
                    }
                    map3.put(modelType, hashSet);
                }
                com.quizlet.infra.legacysyncengine.tasks.parse.h hVar2 = bVar2.h;
                return new h(map3, hVar2.c, hVar2.d);
            default:
                b bVar3 = this.b;
                com.quizlet.infra.legacysyncengine.net.constants.a aVarB2 = bVar3.b();
                HashMap map4 = bVar3.g;
                com.quizlet.infra.legacysyncengine.tasks.parse.f fVar = (com.quizlet.infra.legacysyncengine.tasks.parse.f) bVar3.b;
                fVar.getClass();
                ModelType modelType2 = bVar3.f;
                com.quizlet.infra.legacysyncengine.tasks.parse.h hVarA = new j0(fVar, map4, modelType2, aVarB2).a((ApiThreeWrapper) obj);
                List list = (List) hVarA.b.get(modelType2);
                if (list != null && list.size() > 0) {
                    ((ExecutionRouter) bVar3.a).e(new com.google.firebase.crashlytics.internal.common.i(22, bVar3, list));
                }
                return hVarA;
        }
    }
}

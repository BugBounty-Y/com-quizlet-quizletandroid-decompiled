package com.quizlet.infra.legacysyncengine.net.importer;

import com.google.android.datatransport.cct.internal.s;
import com.quizlet.db.data.models.base.DBModel;
import com.quizlet.db.data.models.identity.ModelIdentity;
import com.quizlet.db.data.models.identity.ModelIdentityCollection;
import com.quizlet.db.data.models.identity.ModelIdentityProvider;
import com.quizlet.db.data.models.persisted.base.ModelType;
import com.quizlet.db.data.net.tasks.ExecutionRouter;
import com.quizlet.infra.legacysyncengine.tasks.parse.h;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/* loaded from: classes3.dex */
public final /* synthetic */ class a implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ s b;

    public /* synthetic */ a(s sVar, int i) {
        this.a = i;
        this.b = sVar;
    }

    @Override // java.lang.Runnable
    public final void run() {
        HashMap map;
        switch (this.a) {
            case 0:
                com.quizlet.infra.legacysyncengine.net.constants.a aVar = com.quizlet.infra.legacysyncengine.net.constants.a.b;
                s sVar = this.b;
                if (aVar.equals((com.quizlet.infra.legacysyncengine.net.constants.a) sVar.h)) {
                    map = new HashMap();
                    h hVar = (h) sVar.g;
                    for (ModelType modelType : hVar.a.keySet()) {
                        Set<ModelIdentity<? extends DBModel>> setIdentitiesForModels = ModelIdentityProvider.identitiesForModels((List) hVar.a.get(modelType));
                        Set<ModelIdentity<? extends DBModel>> setIdentitiesForModels2 = ModelIdentityProvider.identitiesForModels((List) ((Map) sVar.a).get(modelType));
                        for (ModelIdentity<? extends DBModel> modelIdentity : setIdentitiesForModels) {
                            if (!setIdentitiesForModels2.contains(modelIdentity)) {
                                map.putIfAbsent(modelType, new ModelIdentityCollection());
                                ((ModelIdentityCollection) map.get(modelType)).add((ModelIdentity) modelIdentity);
                            }
                        }
                    }
                } else {
                    map = new HashMap();
                }
                if (map.size() > 0) {
                    ((ExecutionRouter) sVar.b).f(new b(sVar, map, 1));
                    break;
                } else {
                    sVar.r();
                    break;
                }
            default:
                this.b.r();
                break;
        }
    }
}

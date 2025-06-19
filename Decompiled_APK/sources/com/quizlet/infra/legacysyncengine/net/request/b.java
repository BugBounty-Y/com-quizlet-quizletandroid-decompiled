package com.quizlet.infra.legacysyncengine.net.request;

import com.google.android.datatransport.cct.internal.s;
import com.quizlet.db.data.database.DatabaseHelper;
import com.quizlet.db.data.models.base.DBModel;
import com.quizlet.db.data.models.persisted.base.ModelType;
import com.quizlet.db.data.net.tasks.ExecutionRouter;
import java.util.HashMap;
import java.util.List;

/* loaded from: classes3.dex */
public abstract class b extends androidx.work.impl.constraints.trackers.e {
    public final ModelType f;
    public final HashMap g;
    public com.quizlet.infra.legacysyncengine.tasks.parse.h h;
    public final DatabaseHelper i;

    public b(ModelType modelType, List list, ExecutionRouter executionRouter, androidx.work.impl.model.c cVar, com.quizlet.infra.legacysyncengine.tasks.parse.f fVar, s sVar, com.squareup.otto.c cVar2, DatabaseHelper databaseHelper) {
        super(executionRouter, cVar, fVar, sVar, cVar2);
        this.i = databaseHelper;
        this.f = modelType;
        HashMap map = new HashMap(list.size());
        this.g = map;
        if (list.size() > 0) {
            map.put(((DBModel) list.get(0)).getModelType(), list);
        }
    }
}

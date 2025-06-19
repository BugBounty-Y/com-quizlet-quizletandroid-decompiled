package com.quizlet.infra.legacysyncengine.managers;

import com.quizlet.db.data.database.DatabaseHelper;
import com.quizlet.db.data.models.base.DBModel;
import com.quizlet.db.data.models.identity.ModelIdentityProvider;
import com.quizlet.db.data.net.tasks.ExecutionRouter;
import com.quizlet.infra.legacysyncengine.models.identity.ModelKeyFieldChangeMapper;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;

/* loaded from: classes3.dex */
public final class i extends e {
    public final ModelKeyFieldChangeMapper e;

    public i(ExecutionRouter executionRouter, DatabaseHelper databaseHelper, ModelIdentityProvider modelIdentityProvider, ModelKeyFieldChangeMapper modelKeyFieldChangeMapper, com.quizlet.infra.legacysyncengine.net.listeners.d dVar) {
        super(executionRouter, databaseHelper, modelIdentityProvider, dVar);
        this.e = modelKeyFieldChangeMapper;
    }

    @Override // com.quizlet.infra.legacysyncengine.managers.e
    public final void b(List list) {
        super.b(list);
        Iterator it2 = list.iterator();
        while (it2.hasNext()) {
            DBModel dBModel = (DBModel) it2.next();
            if (dBModel.getIdentity().hasServerIdentity() || !dBModel.getDeleted()) {
                dBModel.setDirty(true);
            }
        }
        this.e.updateIdsAndForeignKeys(list);
    }

    public final void c(DBModel... dBModelArr) {
        a(Arrays.asList(dBModelArr), null);
    }
}

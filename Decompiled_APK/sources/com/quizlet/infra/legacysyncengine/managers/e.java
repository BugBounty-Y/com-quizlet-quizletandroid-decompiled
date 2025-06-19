package com.quizlet.infra.legacysyncengine.managers;

import androidx.camera.camera2.internal.T;
import com.google.android.gms.internal.ads.RunnableC1788Vd;
import com.quizlet.db.data.database.DatabaseHelper;
import com.quizlet.db.data.models.base.DBModel;
import com.quizlet.db.data.models.identity.ModelIdentityProvider;
import com.quizlet.db.data.net.tasks.ExecutionRouter;
import java.util.Iterator;
import java.util.List;

/* loaded from: classes3.dex */
public abstract class e {
    public final ExecutionRouter a;
    public final DatabaseHelper b;
    public final ModelIdentityProvider c;
    public final com.quizlet.infra.legacysyncengine.net.listeners.d d;

    public e(ExecutionRouter executionRouter, DatabaseHelper databaseHelper, ModelIdentityProvider modelIdentityProvider, com.quizlet.infra.legacysyncengine.net.listeners.d dVar) {
        this.a = executionRouter;
        this.b = databaseHelper;
        this.c = modelIdentityProvider;
        this.d = dVar;
    }

    public final void a(List list, T t) throws Exception {
        b(list);
        new RunnableC1788Vd(list, this.b, this.d, this.a, t, 7).run();
    }

    public void b(List list) {
        Iterator it2 = list.iterator();
        while (it2.hasNext()) {
            this.c.generateLocalIdIfNeeded((DBModel) it2.next());
        }
    }
}

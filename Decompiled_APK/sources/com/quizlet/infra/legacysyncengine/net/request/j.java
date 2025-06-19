package com.quizlet.infra.legacysyncengine.net.request;

import com.google.android.datatransport.cct.internal.s;
import com.onetrust.otpublishers.headless.UI.fragment.q;
import com.quizlet.db.data.database.DatabaseHelper;
import com.quizlet.db.data.models.base.DBModel;
import com.quizlet.db.data.net.tasks.ExecutionRouter;
import com.quizlet.infra.legacysyncengine.models.serializers.ApiThreeRequestSerializer;
import java.io.PipedOutputStream;
import java.util.List;
import okhttp3.A;

/* loaded from: classes3.dex */
public final class j extends b {
    public final s j;
    public final com.quizlet.infra.legacysyncengine.net.constants.a k;

    public j(List list, com.quizlet.infra.legacysyncengine.net.constants.a aVar, ExecutionRouter executionRouter, androidx.work.impl.model.c cVar, com.quizlet.infra.legacysyncengine.tasks.parse.f fVar, s sVar, com.squareup.otto.c cVar2, DatabaseHelper databaseHelper) {
        super(((DBModel) list.get(0)).getModelType(), list, executionRouter, cVar, fVar, sVar, cVar2, databaseHelper);
        this.k = aVar;
        this.j = sVar;
    }

    @Override // androidx.work.impl.constraints.trackers.e
    public final com.quizlet.infra.legacysyncengine.tasks.parse.g a(PipedOutputStream pipedOutputStream) {
        List list = (List) this.g.get(this.f);
        s sVar = this.j;
        sVar.getClass();
        return new com.quizlet.infra.legacysyncengine.tasks.parse.j(list, this.k, pipedOutputStream, (ApiThreeRequestSerializer) sVar.g, (q) sVar.a, (A) sVar.h);
    }

    @Override // androidx.work.impl.constraints.trackers.e
    public final com.quizlet.infra.legacysyncengine.net.constants.a b() {
        return this.k;
    }
}

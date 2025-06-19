package com.quizlet.db.data.models.identity;

import com.quizlet.db.data.models.base.DBModel;
import com.quizlet.db.data.models.persisted.base.ModelType;

/* loaded from: classes2.dex */
public class ServerIdAssignmentEvent {
    public final Long localId;
    public final ModelType<? extends DBModel> modelType;
    public final Long serverId;

    public ServerIdAssignmentEvent(ModelType<? extends DBModel> modelType, Long l, Long l2) {
        this.modelType = modelType;
        this.localId = l;
        this.serverId = l2;
    }
}

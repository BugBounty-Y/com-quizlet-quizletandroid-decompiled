package com.quizlet.db.data.models.legacy;

import com.j256.ormlite.field.DatabaseField;
import com.quizlet.db.data.models.base.BaseDBModel;
import com.quizlet.db.data.models.persisted.base.ModelType;

/* loaded from: classes2.dex */
public abstract class LegacyBaseDBModel extends BaseDBModel {
    public static final String ID_FIELD = "id";
    public static final String LOCAL_ID_FIELD = "localGeneratedId";

    @DatabaseField(columnName = "localGeneratedId")
    private long localId;

    @Override // com.quizlet.db.data.models.base.BaseDBModel, com.quizlet.db.data.models.base.DBModel
    public long getLocalId() {
        return this.localId;
    }

    @Override // com.quizlet.db.data.models.base.BaseDBModel, com.quizlet.db.data.models.base.DBModel
    public ModelType<LegacyBaseDBModel> getModelType() {
        return null;
    }

    @Override // com.quizlet.db.data.models.base.BaseDBModel, com.quizlet.db.data.models.base.DBModel
    public void setLocalId(long j) {
        this.localId = j;
    }
}

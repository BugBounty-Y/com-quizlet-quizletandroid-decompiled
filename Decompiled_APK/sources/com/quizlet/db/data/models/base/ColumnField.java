package com.quizlet.db.data.models.base;

import com.quizlet.db.data.models.base.DBModel;
import com.quizlet.db.data.models.persisted.base.ModelType;

/* loaded from: classes2.dex */
public abstract class ColumnField<M extends DBModel, T> extends ModelField<M, T> {
    protected final String mName;

    public ColumnField(ModelType<M> modelType, String str) {
        super(modelType);
        this.mName = str;
    }

    @Override // com.quizlet.db.data.models.base.ModelField
    public String getDatabaseColumnName() {
        return this.mName;
    }
}

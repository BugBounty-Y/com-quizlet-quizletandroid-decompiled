package com.quizlet.db.data.models.base;

import androidx.annotation.NonNull;
import com.quizlet.db.data.models.base.DBModel;
import com.quizlet.db.data.models.persisted.base.ModelType;

/* loaded from: classes2.dex */
public abstract class ModelField<M extends DBModel, T> {
    protected final ModelType<M> mModelType;

    public ModelField(ModelType<M> modelType) {
        this.mModelType = modelType;
    }

    public String getAPIFieldName() {
        return getDatabaseColumnName();
    }

    public abstract String getDatabaseColumnName();

    public ModelType<M> getModelType() {
        return this.mModelType;
    }

    public abstract T getValue(@NonNull M m);

    public abstract void setValue(@NonNull M m, T t);

    public String toString() {
        return getDatabaseColumnName();
    }
}

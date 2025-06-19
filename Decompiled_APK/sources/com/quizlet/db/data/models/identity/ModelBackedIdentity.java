package com.quizlet.db.data.models.identity;

import androidx.annotation.NonNull;
import com.quizlet.db.data.models.base.DBModel;
import com.quizlet.db.data.models.base.ModelField;
import com.quizlet.db.data.models.persisted.base.ModelType;

/* loaded from: classes2.dex */
public class ModelBackedIdentity<M extends DBModel> extends ModelIdentity<M> {

    @NonNull
    protected final M mModel;

    public ModelBackedIdentity(@NonNull M m) {
        this.mModel = m;
    }

    @Override // com.quizlet.db.data.models.identity.ModelIdentity
    public Long getIdentityFieldValue(ModelField<M, Long> modelField) {
        return modelField.getValue(this.mModel);
    }

    @Override // com.quizlet.db.data.models.identity.ModelIdentity
    public ModelType<M> getModelType() {
        return this.mModel.getModelType();
    }
}

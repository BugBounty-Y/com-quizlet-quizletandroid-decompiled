package com.quizlet.db.data.models.identity;

import com.quizlet.db.data.models.base.DBModel;
import com.quizlet.db.data.models.base.ModelField;
import com.quizlet.db.data.models.persisted.base.ModelType;
import java.util.Collections;
import java.util.Set;

/* loaded from: classes2.dex */
public class UnboundModelSingleFieldIdentity<M extends DBModel> extends ModelIdentity<M> {
    protected final ModelField<M, Long> mIdentityField;
    protected final Long mIdentityValue;

    public UnboundModelSingleFieldIdentity(ModelType<M> modelType, long j) {
        this.mIdentityValue = Long.valueOf(j);
        ModelField<M, Long> singleIdentityField = ModelIdentityProvider.getSingleIdentityField(modelType);
        this.mIdentityField = singleIdentityField;
        if (singleIdentityField != null) {
            return;
        }
        throw new IllegalArgumentException(modelType + " does not have single field identity");
    }

    @Override // com.quizlet.db.data.models.identity.ModelIdentity
    public Long getIdentityFieldValue(ModelField modelField) {
        return this.mIdentityValue;
    }

    @Override // com.quizlet.db.data.models.identity.ModelIdentity
    public Set<ModelField<M, Long>> getIdentityFields() {
        return Collections.singleton(this.mIdentityField);
    }

    @Override // com.quizlet.db.data.models.identity.ModelIdentity
    public ModelType<M> getModelType() {
        return this.mIdentityField.getModelType();
    }

    public UnboundModelSingleFieldIdentity(Long l, ModelField<M, Long> modelField) {
        this.mIdentityValue = l;
        this.mIdentityField = modelField;
    }
}

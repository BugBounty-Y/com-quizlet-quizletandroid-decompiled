package com.quizlet.db.data.models.persisted.base;

import com.quizlet.api.model.ModelWrapper;
import com.quizlet.db.data.models.base.DBModel;
import com.quizlet.db.data.models.base.ModelField;
import com.quizlet.db.data.orm.Include;
import java.util.Collections;
import java.util.List;
import java.util.Set;

/* loaded from: classes2.dex */
public abstract class ModelType<M extends DBModel> {
    public Set<Include> getAutomaticIncludes() {
        return Collections.EMPTY_SET;
    }

    public abstract String getEndpointRoot();

    public abstract Set<ModelField<M, Long>> getIdentityFields();

    public abstract ModelField<M, Long> getLocalIdField();

    public abstract Class<M> getModelClass();

    public abstract List<M> getModels(ModelWrapper modelWrapper);

    public int getSyncPageSize() {
        return 50;
    }

    public boolean hasMultipleFieldIdentity() {
        return getIdentityFields().size() > 1;
    }

    public boolean supportsServerSync() {
        return true;
    }
}

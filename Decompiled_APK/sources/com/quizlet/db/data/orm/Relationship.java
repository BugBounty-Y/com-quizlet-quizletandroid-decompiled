package com.quizlet.db.data.orm;

import com.quizlet.db.data.models.base.DBModel;
import com.quizlet.db.data.models.base.ModelField;
import com.quizlet.db.data.models.identity.ModelIdentity;
import com.quizlet.db.data.models.identity.UnboundModelSingleFieldIdentity;
import com.quizlet.db.data.models.persisted.base.ModelType;
import java.util.List;
import java.util.Locale;
import timber.log.c;

/* loaded from: classes2.dex */
public abstract class Relationship<F extends DBModel, T extends DBModel> extends ModelField<F, Long> {
    private String fromFieldName;
    private List<ModelType<? extends T>> toModelTypes;

    public Relationship(ModelType modelType, String str, List list) {
        super(modelType);
        this.fromFieldName = str;
        this.toModelTypes = list;
    }

    public abstract String getApiAssociationName();

    @Override // com.quizlet.db.data.models.base.ModelField
    public String getDatabaseColumnName() {
        return getFromFieldName();
    }

    public String getFromFieldName() {
        return this.fromFieldName;
    }

    public ModelType<F> getFromModelType() {
        return getModelType();
    }

    public abstract DBModel getModel(DBModel dBModel);

    public ModelIdentity<T> getToModelIdentity(F f) {
        Long l = (Long) getValue(f);
        if (l == null || l.longValue() == 0) {
            return null;
        }
        ModelType toModelType = getToModelType(f);
        if (toModelType != null) {
            return new UnboundModelSingleFieldIdentity(toModelType, l.longValue());
        }
        c.a(new IllegalStateException(String.format(Locale.US, "%s.%s = %d, but foreign model class was null", f, getFromFieldName(), l)));
        return null;
    }

    public abstract ModelType getToModelType(DBModel dBModel);

    public abstract ModelType getToModelType(Long l);

    public List<ModelType<? extends T>> getToModelTypes() {
        return this.toModelTypes;
    }

    public boolean hasModelReference() {
        return true;
    }

    public boolean isRequired() {
        return true;
    }

    public abstract void setModel(DBModel dBModel, DBModel dBModel2);

    public void setToModelIdentity(F f, ModelIdentity<? extends T> modelIdentity) {
        if (modelIdentity == null || getToModelTypes().contains(modelIdentity.getModelType())) {
            setValue(f, Long.valueOf(modelIdentity == null ? 0L : modelIdentity.getSingleFieldIdentityValue().longValue()));
        } else {
            throw new IllegalArgumentException("No relationship configured to " + modelIdentity.getModelType().toString());
        }
    }
}

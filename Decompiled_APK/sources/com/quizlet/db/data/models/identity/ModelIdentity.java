package com.quizlet.db.data.models.identity;

import androidx.annotation.NonNull;
import com.j256.ormlite.stmt.UpdateBuilder;
import com.j256.ormlite.stmt.Where;
import com.j256.ormlite.stmt.query.SimpleComparison;
import com.quizlet.db.data.models.base.DBModel;
import com.quizlet.db.data.models.base.ModelField;
import com.quizlet.db.data.models.persisted.base.ModelType;
import java.sql.SQLException;
import java.util.Iterator;
import java.util.Set;
import org.apache.commons.lang3.builder.b;

/* loaded from: classes2.dex */
public abstract class ModelIdentity<M extends DBModel> {
    public void apply(DBModel dBModel) {
        for (ModelField<M, Long> modelField : getIdentityFields()) {
            modelField.setValue(dBModel, getIdentityFieldValue(modelField));
        }
    }

    public int compareTo(ModelIdentity<M> modelIdentity) {
        for (ModelField<M, Long> modelField : modelIdentity.getIdentityFields()) {
            int iCompareTo = getIdentityFieldValue(modelField).compareTo(modelIdentity.getIdentityFieldValue(modelField));
            if (iCompareTo != 0) {
                return iCompareTo;
            }
        }
        return 0;
    }

    public boolean equals(Object obj) {
        if (obj == null) {
            return false;
        }
        if (obj == this) {
            return true;
        }
        if (!(obj instanceof ModelIdentity)) {
            return false;
        }
        ModelIdentity modelIdentity = (ModelIdentity) obj;
        if (!modelIdentity.getModelType().equals(getModelType())) {
            return false;
        }
        for (ModelField<M, Long> modelField : getIdentityFields()) {
            if (getIdentityFieldValue(modelField).longValue() != modelIdentity.getIdentityFieldValue(modelField).longValue()) {
                return false;
            }
        }
        return true;
    }

    public abstract Long getIdentityFieldValue(ModelField<M, Long> modelField);

    public Set<ModelField<M, Long>> getIdentityFields() {
        return getModelType().getIdentityFields();
    }

    public abstract ModelType<M> getModelType();

    public Long getSingleFieldIdentityValue() {
        Set<ModelField<M, Long>> identityFields = getIdentityFields();
        if (identityFields.size() == 1) {
            return getIdentityFieldValue(identityFields.iterator().next());
        }
        return null;
    }

    public boolean hasServerIdentity() {
        Iterator<ModelField<M, Long>> it2 = getIdentityFields().iterator();
        while (it2.hasNext()) {
            if (getIdentityFieldValue(it2.next()).longValue() <= 0) {
                return false;
            }
        }
        return true;
    }

    public int hashCode() {
        b bVar = new b(467, 937);
        bVar.b(getModelType());
        Iterator<ModelField<M, Long>> it2 = getIdentityFields().iterator();
        while (it2.hasNext()) {
            bVar.b(getIdentityFieldValue(it2.next()));
        }
        return bVar.b;
    }

    @NonNull
    public String toString() {
        return "ModelIdentity<" + getModelType() + SimpleComparison.GREATER_THAN_OPERATION;
    }

    public String urlString() {
        Set<ModelField<M, Long>> identityFields = getIdentityFields();
        if (identityFields.size() == 1) {
            return Long.toString(getIdentityFieldValue(identityFields.iterator().next()).longValue());
        }
        return null;
    }

    public <T, ID> Where<T, ID> whereEq(Where<T, ID> where) throws SQLException {
        int i = 0;
        for (ModelField<M, Long> modelField : getIdentityFields()) {
            int i2 = i + 1;
            if (i > 0) {
                where.and();
            }
            where.eq(modelField.getDatabaseColumnName(), getIdentityFieldValue(modelField));
            i = i2;
        }
        return where;
    }

    public <T, ID> UpdateBuilder<T, ID> apply(UpdateBuilder<T, ID> updateBuilder) throws SQLException {
        for (ModelField<M, Long> modelField : getIdentityFields()) {
            updateBuilder.updateColumnValue(modelField.getDatabaseColumnName(), getIdentityFieldValue(modelField));
        }
        return updateBuilder;
    }
}

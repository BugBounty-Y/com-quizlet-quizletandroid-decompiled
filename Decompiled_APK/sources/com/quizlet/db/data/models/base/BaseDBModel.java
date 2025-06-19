package com.quizlet.db.data.models.base;

import androidx.annotation.NonNull;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.j256.ormlite.field.DatabaseField;
import com.quizlet.data.model.C4115c0;
import com.quizlet.db.data.models.identity.ModelIdentity;
import com.quizlet.db.data.models.persisted.base.ModelType;
import com.quizlet.db.data.models.persisted.fields.BaseDBModelFields;
import java.util.Collections;
import java.util.List;

/* loaded from: classes2.dex */
public abstract class BaseDBModel implements DBModel {

    @DatabaseField(columnName = BaseDBModelFields.Names.CLIENT_TIMESTAMP)
    private long clientTimestamp = System.currentTimeMillis() / 1000;

    @DatabaseField(columnName = "dirty")
    protected boolean dirty;

    @DatabaseField(columnName = "isDeleted")
    protected boolean isDeleted;

    @DatabaseField(columnName = "lastModified")
    private long lastModified;

    @Override // com.quizlet.db.data.models.base.DBModel
    public <M extends DBModel> int compare(@NonNull M m, @NonNull M m2) {
        if (m.getClass() != m2.getClass()) {
            return 0;
        }
        return m.getIdentity().compareTo(m2.getIdentity());
    }

    public boolean equals(Object obj) {
        if (obj == null) {
            return false;
        }
        if (obj == this) {
            return true;
        }
        if (obj.getClass().equals(getClass())) {
            return getIdentity().equals(((BaseDBModel) obj).getIdentity());
        }
        return false;
    }

    @Override // com.quizlet.db.data.models.base.DBModel
    @JsonProperty(BaseDBModelFields.Names.CLIENT_TIMESTAMP)
    public long getClientTimestamp() {
        return this.clientTimestamp;
    }

    @Override // com.quizlet.db.data.models.base.DBModel
    @JsonProperty("isDeleted")
    public boolean getDeleted() {
        return this.isDeleted;
    }

    @Override // com.quizlet.db.data.models.base.DBModel
    public boolean getDirty() {
        return this.dirty;
    }

    @Override // com.quizlet.db.data.models.base.DBModel
    public List<C4115c0> getFilesForRequest() {
        return Collections.EMPTY_LIST;
    }

    @Override // com.quizlet.db.data.models.base.DBModel
    public abstract <M extends DBModel> ModelIdentity<M> getIdentity();

    @Override // com.quizlet.db.data.models.base.DBModel
    @JsonProperty("lastModified")
    public long getLastModified() {
        return this.lastModified;
    }

    @Override // com.quizlet.db.data.models.base.DBModel
    @JsonProperty("clientId")
    public abstract long getLocalId();

    @Override // com.quizlet.db.data.models.base.DBModel
    public abstract <M extends DBModel> ModelType<M> getModelType();

    public int hashCode() {
        return getIdentity().hashCode();
    }

    @Override // com.quizlet.db.data.models.base.DBModel
    public void setClientTimestamp(long j) {
        this.clientTimestamp = j;
    }

    @Override // com.quizlet.db.data.models.base.DBModel
    @JsonProperty("isDeleted")
    public void setDeleted(boolean z) {
        this.isDeleted = z;
    }

    @Override // com.quizlet.db.data.models.base.DBModel
    public void setDirty(boolean z) {
        this.dirty = z;
    }

    @Override // com.quizlet.db.data.models.base.DBModel
    public void setLastModified(long j) {
        this.lastModified = j;
    }

    @Override // com.quizlet.db.data.models.base.DBModel
    public abstract void setLocalId(long j);
}

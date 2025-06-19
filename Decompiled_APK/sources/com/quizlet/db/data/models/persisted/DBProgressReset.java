package com.quizlet.db.data.models.persisted;

import androidx.annotation.NonNull;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.j256.ormlite.field.DatabaseField;
import com.j256.ormlite.table.DatabaseTable;
import com.quizlet.db.data.models.base.BaseDBModel;
import com.quizlet.db.data.models.identity.ModelBackedIdentity;
import com.quizlet.db.data.models.identity.ModelIdentity;
import com.quizlet.db.data.models.persisted.base.ModelType;
import com.quizlet.db.data.models.persisted.base.Models;
import com.quizlet.db.data.models.persisted.fields.DBProgressResetFields;

@JsonIgnoreProperties(ignoreUnknown = true)
@DatabaseTable(tableName = DBProgressReset.TABLE_NAME)
/* loaded from: classes2.dex */
public class DBProgressReset extends BaseDBModel {
    public static final String TABLE_NAME = "progress_reset";

    @DatabaseField(columnName = DBProgressResetFields.Names.CONTAINER_ID, uniqueCombo = true)
    private long containerId;

    @DatabaseField(columnName = DBProgressResetFields.Names.CONTAINER_TYPE, uniqueCombo = true)
    private short containerType;

    @DatabaseField(columnName = "localGeneratedId", id = true)
    private long localId;

    @DatabaseField(columnName = "personId", uniqueCombo = true)
    private long personId;

    @DatabaseField(columnName = DBProgressResetFields.Names.RESET_TIME_SEC)
    private long resetTimeSec;

    @JsonProperty(DBProgressResetFields.Names.CONTAINER_ID)
    public long getContainerId() {
        return this.containerId;
    }

    @JsonProperty(DBProgressResetFields.Names.CONTAINER_TYPE)
    public short getContainerType() {
        return this.containerType;
    }

    @Override // com.quizlet.db.data.models.base.BaseDBModel, com.quizlet.db.data.models.base.DBModel
    @NonNull
    public ModelIdentity<DBProgressReset> getIdentity() {
        return new ModelBackedIdentity(this);
    }

    @Override // com.quizlet.db.data.models.base.BaseDBModel, com.quizlet.db.data.models.base.DBModel
    @JsonIgnore
    public long getLocalId() {
        return this.localId;
    }

    @Override // com.quizlet.db.data.models.base.BaseDBModel, com.quizlet.db.data.models.base.DBModel
    @NonNull
    public ModelType<DBProgressReset> getModelType() {
        return Models.PROGRESS_RESET;
    }

    @JsonProperty("personId")
    public long getPersonId() {
        return this.personId;
    }

    @JsonProperty(DBProgressResetFields.Names.RESET_TIME_SEC)
    public long getResetTimeSec() {
        return this.resetTimeSec;
    }

    @JsonProperty(DBProgressResetFields.Names.CONTAINER_ID)
    public void setContainerId(long j) {
        this.containerId = j;
    }

    @JsonProperty(DBProgressResetFields.Names.CONTAINER_TYPE)
    public void setContainerType(short s) {
        this.containerType = s;
    }

    @Override // com.quizlet.db.data.models.base.BaseDBModel, com.quizlet.db.data.models.base.DBModel
    @JsonIgnore
    public void setLocalId(long j) {
        this.localId = j;
    }

    @JsonProperty("personId")
    public void setPersonId(long j) {
        this.personId = j;
    }

    @JsonProperty(DBProgressResetFields.Names.RESET_TIME_SEC)
    public void setResetTimeSec(long j) {
        this.resetTimeSec = j;
    }
}

package com.quizlet.db.data.models.persisted;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.j256.ormlite.field.DatabaseField;
import com.j256.ormlite.table.DatabaseTable;
import com.quizlet.db.data.models.base.BaseDBModel;
import com.quizlet.db.data.models.identity.ModelBackedIdentity;
import com.quizlet.db.data.models.identity.ModelIdentity;
import com.quizlet.db.data.models.persisted.base.ModelType;
import com.quizlet.db.data.models.persisted.base.Models;

@JsonIgnoreProperties(ignoreUnknown = true)
@DatabaseTable(tableName = DBEnteredSetPassword.TABLE_NAME)
/* loaded from: classes2.dex */
public class DBEnteredSetPassword extends BaseDBModel {
    public static final String TABLE_NAME = "entered_set_password";

    @DatabaseField(columnName = "id", id = true)
    @Deprecated
    private long id;

    @DatabaseField(columnName = "localGeneratedId")
    private long localId;
    private String password;

    @DatabaseField(columnName = "personId", uniqueCombo = true)
    private long personId;

    @DatabaseField(columnName = "setId", uniqueCombo = true)
    private long setId;

    @DatabaseField
    private int timestamp;

    @Override // com.quizlet.db.data.models.base.BaseDBModel, com.quizlet.db.data.models.base.DBModel
    public ModelIdentity<DBEnteredSetPassword> getIdentity() {
        return new ModelBackedIdentity(this);
    }

    @Override // com.quizlet.db.data.models.base.BaseDBModel, com.quizlet.db.data.models.base.DBModel
    public long getLocalId() {
        return this.localId;
    }

    @Override // com.quizlet.db.data.models.base.BaseDBModel, com.quizlet.db.data.models.base.DBModel
    public ModelType<DBEnteredSetPassword> getModelType() {
        return Models.ENTERED_SET_PASSWORD;
    }

    public String getPassword() {
        return this.password;
    }

    public long getPersonId() {
        return this.personId;
    }

    public long getSetId() {
        return this.setId;
    }

    @JsonProperty("timestamp")
    public int getTimestamp() {
        return this.timestamp;
    }

    @Override // com.quizlet.db.data.models.base.BaseDBModel, com.quizlet.db.data.models.base.DBModel
    public void setLocalId(long j) {
        this.localId = j;
        this.id = j;
    }

    public void setPassword(String str) {
        this.password = str;
    }

    public void setPersonId(long j) {
        this.personId = j;
    }

    public void setSetId(long j) {
        this.setId = j;
    }

    public void setTimestamp(int i) {
        this.timestamp = i;
    }
}

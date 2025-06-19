package com.quizlet.db.data.models.persisted;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.j256.ormlite.field.DatabaseField;
import com.j256.ormlite.table.DatabaseTable;
import com.quizlet.db.data.models.base.BaseDBModel;
import com.quizlet.db.data.models.identity.ModelBackedIdentity;
import com.quizlet.db.data.models.identity.ModelIdentity;
import com.quizlet.db.data.models.persisted.base.ModelType;
import com.quizlet.db.data.models.persisted.base.Models;

@JsonIgnoreProperties(ignoreUnknown = true)
@DatabaseTable(tableName = DBBookmark.TABLE_NAME)
/* loaded from: classes2.dex */
public class DBBookmark extends BaseDBModel {
    public static final String TABLE_NAME = "bookmark";

    @DatabaseField(columnName = "folderId", uniqueCombo = true)
    private long folderId;

    @DatabaseField(columnName = "id", id = true)
    @Deprecated
    private long id;

    @DatabaseField(columnName = "localGeneratedId")
    private long localId;
    private DBFolder mFolder;

    @DatabaseField(columnName = "personId", uniqueCombo = true)
    private long personId;

    @DatabaseField
    private Long timestamp;

    public DBFolder getFolder() {
        return this.mFolder;
    }

    public long getFolderId() {
        return this.folderId;
    }

    @Override // com.quizlet.db.data.models.base.BaseDBModel, com.quizlet.db.data.models.base.DBModel
    public ModelIdentity<DBBookmark> getIdentity() {
        return new ModelBackedIdentity(this);
    }

    @Override // com.quizlet.db.data.models.base.BaseDBModel, com.quizlet.db.data.models.base.DBModel
    public long getLocalId() {
        return this.localId;
    }

    @Override // com.quizlet.db.data.models.base.BaseDBModel, com.quizlet.db.data.models.base.DBModel
    public ModelType<DBBookmark> getModelType() {
        return Models.BOOKMARK;
    }

    public long getPersonId() {
        return this.personId;
    }

    public long getTimestamp() {
        return this.timestamp.longValue();
    }

    public void setFolder(DBFolder dBFolder) {
        this.mFolder = dBFolder;
    }

    public void setFolderId(long j) {
        this.folderId = j;
    }

    @Override // com.quizlet.db.data.models.base.BaseDBModel, com.quizlet.db.data.models.base.DBModel
    public void setLocalId(long j) {
        this.localId = j;
        this.id = j;
    }

    public void setPersonId(long j) {
        this.personId = j;
    }

    public void setTimestamp(long j) {
        this.timestamp = Long.valueOf(j);
    }
}

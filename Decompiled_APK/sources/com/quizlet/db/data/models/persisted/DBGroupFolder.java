package com.quizlet.db.data.models.persisted;

import androidx.annotation.NonNull;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.j256.ormlite.field.DatabaseField;
import com.j256.ormlite.table.DatabaseTable;
import com.quizlet.db.data.models.base.BaseDBModel;
import com.quizlet.db.data.models.base.DBModel;
import com.quizlet.db.data.models.identity.ModelBackedIdentity;
import com.quizlet.db.data.models.identity.ModelIdentity;
import com.quizlet.db.data.models.persisted.base.ModelType;
import com.quizlet.db.data.models.persisted.base.Models;
import com.quizlet.db.data.models.persisted.fields.DBGroupFolderFields;
import com.quizlet.db.data.models.persisted.fields.DBGroupMembershipFields;

@JsonIgnoreProperties(ignoreUnknown = true)
@DatabaseTable(tableName = DBGroupFolder.TABLE_NAME)
/* loaded from: classes2.dex */
public class DBGroupFolder extends BaseDBModel {
    public static final String TABLE_NAME = "group_folder";

    @DatabaseField(columnName = DBGroupFolderFields.Names.CAN_EDIT)
    private boolean canEdit;

    @DatabaseField(columnName = "groupId", uniqueCombo = true)
    private long classId;

    @JsonIgnore
    private DBFolder folder;

    @DatabaseField(columnName = "folderId", uniqueCombo = true)
    private long folderId;

    @DatabaseField(columnName = "localGeneratedId", id = true)
    private long localId;

    @DatabaseField(columnName = "timestamp")
    private long timestamp;

    public static DBGroupFolder createNewInstance(long j, long j2) {
        DBGroupFolder dBGroupFolder = new DBGroupFolder();
        dBGroupFolder.setClassId(j);
        dBGroupFolder.setFolderId(j2);
        dBGroupFolder.setCanEdit(false);
        dBGroupFolder.setTimestamp(System.currentTimeMillis() / 1000);
        return dBGroupFolder;
    }

    @Override // com.quizlet.db.data.models.base.BaseDBModel, com.quizlet.db.data.models.base.DBModel
    public <M extends DBModel> int compare(@NonNull M m, @NonNull M m2) {
        return ((m instanceof DBGroupFolder) && (m2 instanceof DBGroupFolder)) ? Long.valueOf(((DBGroupFolder) m).getTimestamp()).compareTo(Long.valueOf(((DBGroupFolder) m2).getTimestamp())) * (-1) : super.compare(m, m2);
    }

    @JsonProperty(DBGroupFolderFields.Names.CAN_EDIT)
    public boolean getCanEdit() {
        return this.canEdit;
    }

    @JsonProperty(DBGroupMembershipFields.Names.CLASS_ID)
    public long getClassId() {
        return this.classId;
    }

    @JsonIgnore
    public DBFolder getFolder() {
        return this.folder;
    }

    @JsonProperty("folderId")
    public long getFolderId() {
        return this.folderId;
    }

    @Override // com.quizlet.db.data.models.base.BaseDBModel, com.quizlet.db.data.models.base.DBModel
    @NonNull
    public ModelIdentity<DBGroupFolder> getIdentity() {
        return new ModelBackedIdentity(this);
    }

    @Override // com.quizlet.db.data.models.base.BaseDBModel, com.quizlet.db.data.models.base.DBModel
    @JsonIgnore
    public long getLocalId() {
        return this.localId;
    }

    @Override // com.quizlet.db.data.models.base.BaseDBModel, com.quizlet.db.data.models.base.DBModel
    @NonNull
    public ModelType<DBGroupFolder> getModelType() {
        return Models.GROUP_FOLDER;
    }

    @JsonProperty("addedTimestamp")
    public long getTimestamp() {
        return this.timestamp;
    }

    @JsonProperty(DBGroupFolderFields.Names.CAN_EDIT)
    public void setCanEdit(boolean z) {
        this.canEdit = z;
    }

    @JsonProperty(DBGroupMembershipFields.Names.CLASS_ID)
    public void setClassId(long j) {
        this.classId = j;
    }

    @JsonIgnore
    public void setFolder(DBFolder dBFolder) {
        this.folder = dBFolder;
    }

    @JsonProperty("folderId")
    public void setFolderId(long j) {
        this.folderId = j;
    }

    @Override // com.quizlet.db.data.models.base.BaseDBModel, com.quizlet.db.data.models.base.DBModel
    @JsonIgnore
    public void setLocalId(long j) {
        this.localId = j;
    }

    @JsonProperty("addedTimestamp")
    public void setTimestamp(long j) {
        this.timestamp = j;
    }
}

package com.quizlet.db.data.models.persisted;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.j256.ormlite.field.DatabaseField;
import com.j256.ormlite.table.DatabaseTable;
import com.quizlet.db.data.models.base.BaseDBModel;
import com.quizlet.db.data.models.identity.ModelBackedIdentity;
import com.quizlet.db.data.models.identity.ModelIdentity;
import com.quizlet.db.data.models.interfaces.FeedItem;
import com.quizlet.db.data.models.persisted.base.ModelType;
import com.quizlet.db.data.models.persisted.base.Models;
import com.quizlet.db.data.models.persisted.fields.DBGroupFolderFields;
import com.quizlet.db.data.models.persisted.fields.DBGroupMembershipFields;
import com.quizlet.db.data.models.persisted.fields.DBGroupSetFields;

@JsonIgnoreProperties(ignoreUnknown = true)
@DatabaseTable(tableName = DBGroupSet.TABLE_NAME)
/* loaded from: classes2.dex */
public class DBGroupSet extends BaseDBModel implements FeedItem {
    public static final String TABLE_NAME = "group_set";

    @DatabaseField
    boolean canEdit;

    @DatabaseField(columnName = "groupId", uniqueCombo = true)
    private long classId;

    @DatabaseField(columnName = "folderId")
    private Long folderId;

    @DatabaseField(columnName = "id", id = true)
    @Deprecated
    private long id;

    @DatabaseField(columnName = "localGeneratedId")
    private long localId;
    private DBGroup mGroup;
    private DBStudySet mSet;
    private DBUser mUser;

    @DatabaseField(columnName = "setId", uniqueCombo = true)
    private long setId;

    @DatabaseField(columnName = DBGroupSetFields.Names.TIMESTAMP)
    long timestamp;

    @DatabaseField(columnName = "userId")
    long userId;

    public static DBGroupSet createNewInstance(long j, long j2, long j3) {
        DBGroupSet dBGroupSet = new DBGroupSet();
        dBGroupSet.setClassId(j);
        dBGroupSet.setSetId(j2);
        dBGroupSet.setUserId(j3);
        dBGroupSet.setFolderId(null);
        dBGroupSet.setCanEdit(false);
        dBGroupSet.setTimestamp(System.currentTimeMillis() / 1000);
        return dBGroupSet;
    }

    public boolean getCanEdit() {
        return this.canEdit;
    }

    @JsonProperty(DBGroupMembershipFields.Names.CLASS_ID)
    public long getClassId() {
        return this.classId;
    }

    @Override // com.quizlet.db.data.models.interfaces.FeedItem
    @JsonIgnore
    public Object getFeedId() {
        return this.classId + "-" + this.setId;
    }

    @JsonProperty("folderId")
    public Long getFolderId() {
        return this.folderId;
    }

    public DBGroup getGroup() {
        return this.mGroup;
    }

    @Override // com.quizlet.db.data.models.base.BaseDBModel, com.quizlet.db.data.models.base.DBModel
    public ModelIdentity<DBGroupSet> getIdentity() {
        return new ModelBackedIdentity(this);
    }

    @Override // com.quizlet.db.data.models.base.BaseDBModel, com.quizlet.db.data.models.base.DBModel
    public long getLocalId() {
        return this.localId;
    }

    @Override // com.quizlet.db.data.models.base.BaseDBModel, com.quizlet.db.data.models.base.DBModel
    public ModelType<DBGroupSet> getModelType() {
        return Models.GROUP_SET;
    }

    @Override // com.quizlet.db.data.models.interfaces.FeedItem
    public DBStudySet getSet() {
        return this.mSet;
    }

    @Override // com.quizlet.db.data.models.interfaces.FeedItem
    public long getSetId() {
        return this.setId;
    }

    @Override // com.quizlet.db.data.models.interfaces.FeedItem
    @JsonIgnore
    public long getSortTimestamp() {
        return getTimestamp();
    }

    public long getTimestamp() {
        return this.timestamp;
    }

    public DBUser getUser() {
        return this.mUser;
    }

    public long getUserId() {
        return this.userId;
    }

    @JsonProperty(DBGroupFolderFields.Names.CAN_EDIT)
    public void setCanEdit(boolean z) {
        this.canEdit = z;
    }

    public void setClassId(long j) {
        this.classId = j;
    }

    @JsonProperty("folderId")
    public void setFolderId(Long l) {
        this.folderId = l;
    }

    public void setGroup(DBGroup dBGroup) {
        this.mGroup = dBGroup;
    }

    @Override // com.quizlet.db.data.models.base.BaseDBModel, com.quizlet.db.data.models.base.DBModel
    public void setLocalId(long j) {
        this.localId = j;
        this.id = j;
    }

    public void setSet(DBStudySet dBStudySet) {
        this.mSet = dBStudySet;
    }

    @JsonProperty("setId")
    public void setSetId(long j) {
        this.setId = j;
    }

    @JsonProperty("timestamp")
    public void setTimestamp(long j) {
        this.timestamp = j;
    }

    public void setUser(DBUser dBUser) {
        this.mUser = dBUser;
    }

    @JsonProperty("userId")
    public void setUserId(long j) {
        this.userId = j;
    }
}

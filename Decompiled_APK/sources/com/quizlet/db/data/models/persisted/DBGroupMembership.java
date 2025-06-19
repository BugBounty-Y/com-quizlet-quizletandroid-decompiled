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
import com.quizlet.db.data.models.persisted.fields.DBGroupMembershipFields;

@JsonIgnoreProperties(ignoreUnknown = true)
@DatabaseTable(tableName = DBGroupMembership.TABLE_NAME)
/* loaded from: classes2.dex */
public class DBGroupMembership extends BaseDBModel {
    public static final int LEVEL_ADMIN = 3;
    public static final int LEVEL_APPLICANT = 0;
    public static final int LEVEL_CREATOR = 4;
    public static final int LEVEL_MEMBER = 1;
    public static final int LEVEL_REJECTED = -1;
    public static final int LEVEL_REMOVED = -2;
    public static final int LEVEL_UNINVOLVED = -3;
    public static final int LEVEL_UNKNOWN = -4;
    public static final String TABLE_NAME = "group_membership";

    @DatabaseField(columnName = DBGroupMembershipFields.Names.CLASS_ID, uniqueCombo = true)
    private long classId;

    @DatabaseField(columnName = "id", id = true)
    @Deprecated
    private long id;

    @DatabaseField
    private int lastVisited;

    @DatabaseField
    private int level = 0;

    @DatabaseField(columnName = "localGeneratedId")
    private long localId;
    private DBGroup mGroup;
    private DBUser mUser;

    @DatabaseField
    private boolean receiveEmail;

    @DatabaseField
    private int timestamp;

    @DatabaseField(columnName = "userId", uniqueCombo = true)
    private long userId;

    public static DBGroupMembership makeGroupMembership(long j, long j2, int i) {
        DBGroupMembership dBGroupMembership = new DBGroupMembership();
        dBGroupMembership.setUserId(j);
        dBGroupMembership.setClassId(j2);
        dBGroupMembership.setLevel(i);
        return dBGroupMembership;
    }

    @JsonProperty(DBGroupMembershipFields.Names.CLASS_ID)
    public long getClassId() {
        return this.classId;
    }

    public DBGroup getGroup() {
        return this.mGroup;
    }

    @Override // com.quizlet.db.data.models.base.BaseDBModel, com.quizlet.db.data.models.base.DBModel
    public ModelIdentity<DBGroupMembership> getIdentity() {
        return new ModelBackedIdentity(this);
    }

    @JsonProperty("lastVisited")
    public int getLastVisited() {
        return this.lastVisited;
    }

    @JsonProperty("level")
    public int getLevel() {
        return this.level;
    }

    @Override // com.quizlet.db.data.models.base.BaseDBModel, com.quizlet.db.data.models.base.DBModel
    public long getLocalId() {
        return this.localId;
    }

    @Override // com.quizlet.db.data.models.base.BaseDBModel, com.quizlet.db.data.models.base.DBModel
    public ModelType<DBGroupMembership> getModelType() {
        return Models.GROUP_MEMBERSHIP;
    }

    @JsonProperty("receiveEmail")
    public boolean getReceiveEmail() {
        return this.receiveEmail;
    }

    @JsonProperty("timestamp")
    public int getTimestamp() {
        return this.timestamp;
    }

    public DBUser getUser() {
        return this.mUser;
    }

    @JsonProperty("userId")
    public long getUserId() {
        return this.userId;
    }

    public boolean isAdmin() {
        return this.level > 1;
    }

    public boolean isApplicant() {
        return this.level == 0;
    }

    public boolean isInvolved() {
        return this.level > 0;
    }

    public boolean isKickedOut() {
        return this.level < 0;
    }

    public void setClassId(long j) {
        this.classId = j;
    }

    public void setGroup(DBGroup dBGroup) {
        this.mGroup = dBGroup;
    }

    public void setLastVisited(int i) {
        this.lastVisited = i;
    }

    public void setLevel(int i) {
        this.level = i;
    }

    @Override // com.quizlet.db.data.models.base.BaseDBModel, com.quizlet.db.data.models.base.DBModel
    public void setLocalId(long j) {
        this.localId = j;
        this.id = j;
    }

    public void setReceiveEmail(boolean z) {
        this.receiveEmail = z;
    }

    public void setTimestamp(int i) {
        this.timestamp = i;
    }

    public void setUser(DBUser dBUser) {
        this.mUser = dBUser;
    }

    public void setUserId(long j) {
        this.userId = j;
    }
}

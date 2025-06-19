package com.quizlet.db.data.models.persisted;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.j256.ormlite.field.DatabaseField;
import com.j256.ormlite.table.DatabaseTable;
import com.quizlet.db.data.models.base.BaseDBModel;
import com.quizlet.db.data.models.identity.ModelBackedIdentity;
import com.quizlet.db.data.models.identity.ModelIdentity;
import com.quizlet.db.data.models.persisted.base.ModelType;
import com.quizlet.db.data.models.persisted.base.Models;
import com.quizlet.db.data.models.persisted.fields.DBFolderFields;
import com.quizlet.db.data.models.persisted.fields.DBGroupFields;

@JsonIgnoreProperties(ignoreUnknown = true)
@DatabaseTable(tableName = DBGroup.TABLE_NAME)
/* loaded from: classes2.dex */
public class DBGroup extends BaseDBModel {
    public static final String TABLE_NAME = "group";

    @DatabaseField
    private boolean adminOnly;

    @DatabaseField(columnName = DBGroupFields.Names.AUTO_JOIN_LINK)
    private String autoJoinLink;

    @DatabaseField
    private int createdDate;
    private DBUser creator;

    @DatabaseField(columnName = "creatorId")
    private long creatorId;

    @DatabaseField
    private String description;

    @DatabaseField(columnName = "id", id = true)
    private long id;

    @DatabaseField(columnName = "localGeneratedId")
    private long localId;
    private DBSchool mSchool;

    @DatabaseField
    private String name;

    @DatabaseField(columnName = DBGroupFields.Names.NUM_MEMBERS)
    private int numMembers;

    @DatabaseField(columnName = DBGroupFields.Names.NUM_SETS)
    private int numSets;

    @DatabaseField(columnName = DBGroupFields.Names.SCHOOL_ID)
    private long schoolId;

    public static DBGroup makeGroup(DBUser dBUser, String str, boolean z, DBSchool dBSchool, String str2) {
        DBGroup dBGroup = new DBGroup();
        dBGroup.setCreator(dBUser);
        dBGroup.setCreatorId(dBUser.getId());
        dBGroup.setTitle(str);
        if (dBSchool != null) {
            dBGroup.setSchool(dBSchool);
            dBGroup.setSchoolId(dBSchool.getId());
        }
        if (str2 != null) {
            dBGroup.setDescription(str2);
        }
        dBGroup.setAdminOnly(z);
        return dBGroup;
    }

    @JsonProperty("restrictsPosting")
    public boolean getAdminOnly() {
        return this.adminOnly;
    }

    @JsonProperty(DBGroupFields.Names.AUTO_JOIN_LINK)
    public String getAutoJoinLink() {
        return this.autoJoinLink;
    }

    @JsonProperty("timestamp")
    public int getCreatedDate() {
        return this.createdDate;
    }

    public DBUser getCreator() {
        return this.creator;
    }

    @JsonProperty("creatorId")
    public long getCreatorId() {
        return this.creatorId;
    }

    public String getDescription() {
        return this.description;
    }

    @JsonIgnore
    public long getId() {
        return this.id;
    }

    @Override // com.quizlet.db.data.models.base.BaseDBModel, com.quizlet.db.data.models.base.DBModel
    public ModelIdentity<DBGroup> getIdentity() {
        return new ModelBackedIdentity(this);
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    @JsonProperty("id")
    public Long getJsonId() {
        long j = this.id;
        if (j > 0) {
            return Long.valueOf(j);
        }
        return null;
    }

    @Override // com.quizlet.db.data.models.base.BaseDBModel, com.quizlet.db.data.models.base.DBModel
    public long getLocalId() {
        return this.localId;
    }

    @Override // com.quizlet.db.data.models.base.BaseDBModel, com.quizlet.db.data.models.base.DBModel
    public ModelType<DBGroup> getModelType() {
        return Models.GROUP;
    }

    @JsonProperty("_numMembers")
    public int getNumMembers() {
        return this.numMembers;
    }

    @JsonProperty(DBFolderFields.Names.NUM_SETS)
    public int getNumSets() {
        return this.numSets;
    }

    @JsonIgnore
    public DBSchool getSchool() {
        return this.mSchool;
    }

    @JsonProperty(DBGroupFields.Names.SCHOOL_ID)
    public long getSchoolId() {
        return this.schoolId;
    }

    @JsonProperty("title")
    public String getTitle() {
        return this.name;
    }

    public void setAdminOnly(boolean z) {
        this.adminOnly = z;
    }

    public void setCreatedDate(int i) {
        this.createdDate = i;
    }

    public void setCreator(DBUser dBUser) {
        this.creator = dBUser;
    }

    public void setCreatorId(long j) {
        this.creatorId = j;
    }

    public void setDescription(String str) {
        this.description = str;
    }

    public void setId(long j) {
        this.id = j;
    }

    public void setJsonId(Long l) {
        this.id = l.longValue();
    }

    @Override // com.quizlet.db.data.models.base.BaseDBModel, com.quizlet.db.data.models.base.DBModel
    public void setLocalId(long j) {
        this.localId = j;
    }

    public void setNumMembers(int i) {
        this.numMembers = i;
    }

    public void setNumSets(int i) {
        this.numSets = i;
    }

    public void setSchool(DBSchool dBSchool) {
        this.mSchool = dBSchool;
    }

    public void setSchoolId(long j) {
        this.schoolId = j;
    }

    public void setTitle(String str) {
        this.name = str;
    }

    public String toString() {
        return getTitle();
    }
}

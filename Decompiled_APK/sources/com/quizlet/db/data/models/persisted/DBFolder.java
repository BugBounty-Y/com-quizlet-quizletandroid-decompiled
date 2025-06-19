package com.quizlet.db.data.models.persisted;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.j256.ormlite.field.DatabaseField;
import com.j256.ormlite.table.DatabaseTable;
import com.quizlet.db.data.models.base.BaseDBModel;
import com.quizlet.db.data.models.base.Comparators;
import com.quizlet.db.data.models.identity.ModelBackedIdentity;
import com.quizlet.db.data.models.identity.ModelIdentity;
import com.quizlet.db.data.models.interfaces.StudyableModel;
import com.quizlet.db.data.models.persisted.base.ModelType;
import com.quizlet.db.data.models.persisted.base.Models;
import com.quizlet.db.data.models.persisted.fields.DBFolderFields;
import com.quizlet.generated.enums.G1;
import java.util.Collections;
import java.util.List;

@JsonIgnoreProperties(ignoreUnknown = true)
@DatabaseTable(tableName = "folder")
/* loaded from: classes2.dex */
public class DBFolder extends BaseDBModel implements StudyableModel<DBFolder> {
    public static final String TABLE_NAME = "folder";

    @DatabaseField
    private String description;

    @DatabaseField(columnName = "id", id = true)
    private long id;

    @DatabaseField(columnName = DBFolderFields.Names.IS_COURSE_POWERED)
    private boolean isCoursePowered;

    @DatabaseField
    private boolean isHidden;

    @DatabaseField(columnName = "localGeneratedId")
    private long localId;
    private DBUser mPerson;

    @DatabaseField
    private String name;

    @DatabaseField(columnName = DBFolderFields.Names.NUM_SETS)
    @JsonIgnore
    private Integer numStudySets;

    @DatabaseField(columnName = "personId")
    private long personId = 0;

    @DatabaseField(columnName = DBFolderFields.Names.QPF_GENERATION_METHOD)
    @JsonIgnore
    private int qpfGenerationMethod;

    @DatabaseField(columnName = DBFolderFields.Names.SCHOOL_COURSE_DESCRIPTION)
    @JsonIgnore
    private String schoolCourseDescription;

    @DatabaseField
    private long timestamp;

    @DatabaseField(columnName = "_webUrl")
    private String webUrl;

    private DBFolder() {
    }

    public static DBFolder create(long j, String str, String str2) {
        DBFolder dBFolder = new DBFolder();
        dBFolder.setPersonId(j);
        dBFolder.setName(str);
        dBFolder.setDescription(str2);
        dBFolder.setIsHidden(false);
        return dBFolder;
    }

    public static void sortByName(List<DBFolder> list) {
        Collections.sort(list, Comparators.DEFAULT_DESC);
    }

    @Override // com.quizlet.db.data.models.interfaces.StudyableModel
    @JsonIgnore
    public String getDefLang() {
        throw new UnsupportedOperationException("Do not use this");
    }

    public String getDescription() {
        return this.description;
    }

    @JsonIgnore
    public long getId() {
        return this.id;
    }

    @Override // com.quizlet.db.data.models.base.BaseDBModel, com.quizlet.db.data.models.base.DBModel
    public ModelIdentity<DBFolder> getIdentity() {
        return new ModelBackedIdentity(this);
    }

    public boolean getIsCoursePowered() {
        return this.isCoursePowered;
    }

    public boolean getIsHidden() {
        return this.isHidden;
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
    public ModelType<DBFolder> getModelType() {
        return Models.FOLDER;
    }

    public String getName() {
        return this.name;
    }

    @JsonIgnore
    public Integer getNumStudySets() {
        return this.numStudySets;
    }

    public DBUser getPerson() {
        return this.mPerson;
    }

    public long getPersonId() {
        return this.personId;
    }

    public int getQpfGenerationMethod() {
        return this.qpfGenerationMethod;
    }

    @JsonIgnore
    public String getSchoolCourseDescription() {
        return this.schoolCourseDescription;
    }

    @Override // com.quizlet.db.data.models.interfaces.StudyableModel
    @JsonIgnore
    public Long getStudyableId() {
        return Long.valueOf(getId());
    }

    @Override // com.quizlet.db.data.models.interfaces.StudyableModel
    @JsonIgnore
    public G1 getStudyableType() {
        return G1.FOLDER;
    }

    public long getTimestamp() {
        return this.timestamp;
    }

    @Override // com.quizlet.db.data.models.interfaces.StudyableModel
    public String getTitle() {
        return getName();
    }

    @JsonProperty("_webUrl")
    public String getWebUrl() {
        return this.webUrl;
    }

    @Override // com.quizlet.db.data.models.interfaces.StudyableModel
    @JsonIgnore
    public String getWordLang() {
        throw new UnsupportedOperationException("Do not use this");
    }

    public void setDescription(String str) {
        this.description = str;
    }

    public void setId(long j) {
        this.id = j;
    }

    public void setIsCoursePowered(boolean z) {
        this.isCoursePowered = z;
    }

    public void setIsHidden(boolean z) {
        this.isHidden = z;
    }

    public void setJsonId(Long l) {
        this.id = l.longValue();
    }

    @Override // com.quizlet.db.data.models.base.BaseDBModel, com.quizlet.db.data.models.base.DBModel
    public void setLocalId(long j) {
        this.localId = j;
    }

    public void setName(String str) {
        this.name = str;
    }

    @JsonIgnore
    public void setNumStudySets(Integer num) {
        this.numStudySets = num;
    }

    public void setPerson(DBUser dBUser) {
        this.mPerson = dBUser;
    }

    public void setPersonId(long j) {
        this.personId = j;
    }

    public void setQpfGenerationMethod(int i) {
        this.qpfGenerationMethod = i;
    }

    @JsonIgnore
    public void setSchoolCourseDescription(String str) {
        this.schoolCourseDescription = str;
    }

    public void setTimestamp(long j) {
        this.timestamp = j;
    }

    public void setWebUrl(String str) {
        this.webUrl = str;
    }

    public static DBFolder create(DBUser dBUser, String str, String str2) {
        DBFolder dBFolder = new DBFolder();
        dBFolder.setPerson(dBUser);
        dBFolder.setName(str);
        dBFolder.setDescription(str2);
        dBFolder.setIsHidden(false);
        return dBFolder;
    }
}

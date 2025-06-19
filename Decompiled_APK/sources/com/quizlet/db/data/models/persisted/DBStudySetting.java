package com.quizlet.db.data.models.persisted;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.j256.ormlite.field.DatabaseField;
import com.j256.ormlite.table.DatabaseTable;
import com.quizlet.db.data.models.base.BaseDBModel;
import com.quizlet.db.data.models.identity.ModelBackedIdentity;
import com.quizlet.db.data.models.identity.ModelIdentity;
import com.quizlet.db.data.models.interfaces.StudyableModel;
import com.quizlet.db.data.models.persisted.base.ModelType;
import com.quizlet.db.data.models.persisted.base.Models;
import com.quizlet.db.data.models.persisted.fields.DBStudySettingFields;
import com.quizlet.generated.enums.E1;
import com.quizlet.generated.enums.G1;

@JsonIgnoreProperties(ignoreUnknown = true)
@DatabaseTable(tableName = DBStudySetting.TABLE_NAME)
/* loaded from: classes2.dex */
public class DBStudySetting extends BaseDBModel {
    public static final String TABLE_NAME = "study_setting";

    @DatabaseField(columnName = "localGeneratedId", id = true)
    private long localId;

    @DatabaseField(columnName = "personId", uniqueCombo = true)
    private long personId;

    @DatabaseField(columnName = DBStudySettingFields.Names.SETTING_TYPE, uniqueCombo = true)
    private int settingType;

    @DatabaseField(columnName = DBStudySettingFields.Names.SETTING_VALUE)
    private long settingValue;

    @DatabaseField(columnName = DBStudySettingFields.Names.STUDYABLE_ID, uniqueCombo = true)
    private long studyableId;
    private StudyableModel studyableModel;

    @DatabaseField(columnName = DBStudySettingFields.Names.STUDYABLE_TYPE, uniqueCombo = true)
    private int studyableType;

    @DatabaseField
    private long timestamp;

    public DBStudySetting() {
    }

    @Override // com.quizlet.db.data.models.base.BaseDBModel, com.quizlet.db.data.models.base.DBModel
    public ModelIdentity<DBStudySetting> getIdentity() {
        return new ModelBackedIdentity(this);
    }

    @Override // com.quizlet.db.data.models.base.BaseDBModel, com.quizlet.db.data.models.base.DBModel
    public long getLocalId() {
        return this.localId;
    }

    @Override // com.quizlet.db.data.models.base.BaseDBModel, com.quizlet.db.data.models.base.DBModel
    public ModelType<DBStudySetting> getModelType() {
        return Models.STUDY_SETTING;
    }

    public long getPersonId() {
        return this.personId;
    }

    public int getSettingType() {
        return this.settingType;
    }

    public long getSettingValue() {
        return this.settingValue;
    }

    public long getStudyableId() {
        return this.studyableId;
    }

    @JsonIgnore
    public StudyableModel getStudyableModel() {
        return this.studyableModel;
    }

    public int getStudyableType() {
        return this.studyableType;
    }

    public long getTimestamp() {
        return this.timestamp;
    }

    @Override // com.quizlet.db.data.models.base.BaseDBModel, com.quizlet.db.data.models.base.DBModel
    public void setLocalId(long j) {
        this.localId = j;
    }

    public void setPersonId(long j) {
        this.personId = j;
    }

    public void setSettingType(int i) {
        this.settingType = i;
    }

    public void setSettingValue(long j) {
        this.settingValue = j;
    }

    public void setStudyableId(long j) {
        this.studyableId = j;
    }

    public void setStudyableModel(StudyableModel studyableModel) {
        this.studyableModel = studyableModel;
    }

    public void setStudyableType(int i) {
        this.studyableType = i;
    }

    public void setTimestamp(long j) {
        this.timestamp = j;
    }

    public DBStudySetting(Long l, G1 g1, Long l2, E1 e1, Long l3) {
        this.studyableId = l.longValue();
        this.studyableType = g1.b();
        this.personId = l2.longValue();
        this.settingType = e1.a();
        this.settingValue = l3.longValue();
    }
}

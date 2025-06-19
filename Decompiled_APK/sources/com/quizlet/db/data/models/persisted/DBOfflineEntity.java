package com.quizlet.db.data.models.persisted;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.j256.ormlite.field.DatabaseField;
import com.j256.ormlite.table.DatabaseTable;
import com.quizlet.db.data.models.base.BaseDBModel;
import com.quizlet.db.data.models.identity.ModelBackedIdentity;
import com.quizlet.db.data.models.identity.ModelIdentity;
import com.quizlet.db.data.models.interfaces.StudyableModel;
import com.quizlet.db.data.models.persisted.base.ModelType;
import com.quizlet.db.data.models.persisted.base.Models;
import com.quizlet.db.data.models.persisted.fields.DBOfflineEntityFields;
import com.quizlet.generated.enums.G1;

@DatabaseTable(tableName = DBOfflineEntity.TABLE_NAME)
/* loaded from: classes2.dex */
public class DBOfflineEntity extends BaseDBModel {
    public static final String TABLE_NAME = "offline_entity";

    @DatabaseField(columnName = "localGeneratedId", id = true)
    private long localId;

    @DatabaseField(columnName = DBOfflineEntityFields.Names.OFFLINE_STATUS)
    private int offlineStatus;

    @DatabaseField(columnName = DBOfflineEntityFields.Names.MODEL_ID, uniqueCombo = true)
    private long savedModelId;

    @DatabaseField(columnName = DBOfflineEntityFields.Names.MODEL_TYPE, uniqueCombo = true)
    private int savedModelType;
    private StudyableModel studyableModel;

    private DBOfflineEntity() {
    }

    public static DBOfflineEntity create(StudyableModel studyableModel, int i) {
        return create(studyableModel.getStudyableId(), studyableModel.getStudyableType(), i);
    }

    @Override // com.quizlet.db.data.models.base.BaseDBModel, com.quizlet.db.data.models.base.DBModel
    public ModelIdentity<DBOfflineEntity> getIdentity() {
        return new ModelBackedIdentity(this);
    }

    @Override // com.quizlet.db.data.models.base.BaseDBModel, com.quizlet.db.data.models.base.DBModel
    public long getLocalId() {
        return this.localId;
    }

    @Override // com.quizlet.db.data.models.base.BaseDBModel, com.quizlet.db.data.models.base.DBModel
    public ModelType<DBOfflineEntity> getModelType() {
        return Models.OFFLINE_ENTITY;
    }

    public int getOfflineStatus() {
        return this.offlineStatus;
    }

    public long getSavedModelId() {
        return this.savedModelId;
    }

    public int getSavedModelType() {
        return this.savedModelType;
    }

    @JsonIgnore
    public StudyableModel getStudyableModel() {
        return this.studyableModel;
    }

    @Override // com.quizlet.db.data.models.base.BaseDBModel, com.quizlet.db.data.models.base.DBModel
    public void setLocalId(long j) {
        this.localId = j;
    }

    public void setOfflineStatus(int i) {
        this.offlineStatus = i;
    }

    public void setSavedModelId(long j) {
        this.savedModelId = j;
    }

    public void setSavedModelType(int i) {
        this.savedModelType = i;
    }

    public void setStudyableModel(StudyableModel studyableModel) {
        this.studyableModel = studyableModel;
    }

    public static DBOfflineEntity create(Long l, G1 g1, int i) {
        DBOfflineEntity dBOfflineEntity = new DBOfflineEntity();
        dBOfflineEntity.setSavedModelId(l.longValue());
        dBOfflineEntity.setSavedModelType(g1.b());
        dBOfflineEntity.setOfflineStatus(i);
        return dBOfflineEntity;
    }
}

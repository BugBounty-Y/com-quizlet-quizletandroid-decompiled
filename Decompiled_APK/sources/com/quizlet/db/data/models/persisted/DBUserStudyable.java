package com.quizlet.db.data.models.persisted;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.j256.ormlite.field.DatabaseField;
import com.j256.ormlite.table.DatabaseTable;
import com.quizlet.db.data.models.base.BaseDBModel;
import com.quizlet.db.data.models.identity.ModelBackedIdentity;
import com.quizlet.db.data.models.identity.ModelIdentity;
import com.quizlet.db.data.models.interfaces.StudyableModel;
import com.quizlet.db.data.models.persisted.base.ModelType;
import com.quizlet.db.data.models.persisted.base.Models;
import com.quizlet.db.data.models.persisted.fields.DBUserStudyableFields;
import java.util.concurrent.TimeUnit;

@JsonIgnoreProperties(ignoreUnknown = true)
@DatabaseTable(tableName = DBUserStudyable.TABLE_NAME)
/* loaded from: classes2.dex */
public class DBUserStudyable extends BaseDBModel {
    public static final int NOTIFICATIONS_DISABLED = 0;
    public static final int NOTIFICATIONS_ENABLED = 1;
    public static final String TABLE_NAME = "userStudyable";

    @DatabaseField(columnName = DBUserStudyableFields.Names.DUE_TIMESTAMP)
    private Long dueTimestampSec;

    @DatabaseField(columnName = DBUserStudyableFields.Names.IS_ACTIVE)
    private Integer isActive;

    @DatabaseField(columnName = DBUserStudyableFields.Names.IS_DISMISSED)
    private Boolean isDismissed;

    @DatabaseField(columnName = DBUserStudyableFields.Names.LAST_STUDIED_TIMESTAMP)
    private Long lastStudiedTimestamp;

    @DatabaseField(columnName = "localGeneratedId", id = true)
    private long localId;

    @DatabaseField(columnName = DBUserStudyableFields.Names.NOTIFICATION_STATUS)
    private Integer notificationStatus;

    @DatabaseField(columnName = "personId", uniqueCombo = true)
    private Long personId;

    @DatabaseField(columnName = "startTimestamp")
    private Long startTimestampSec;

    @DatabaseField(columnName = DBUserStudyableFields.Names.STUDYABLE_ID, uniqueCombo = true)
    private Long studyableId;
    private StudyableModel studyableModel;

    @DatabaseField(columnName = DBUserStudyableFields.Names.STUDYABLE_TYPE, uniqueCombo = true)
    private Integer studyableType;

    @DatabaseField(columnName = "timestamp")
    private Long timestamp;

    public DBUserStudyable() {
    }

    public Long getDueDateTimestampMilliSec() {
        Long l = this.dueTimestampSec;
        if (l == null || l.longValue() == 0) {
            return null;
        }
        return Long.valueOf(TimeUnit.SECONDS.toMillis(this.dueTimestampSec.longValue()));
    }

    @JsonProperty(DBUserStudyableFields.Names.DUE_TIMESTAMP)
    public Long getDueTimestampSec() {
        return this.dueTimestampSec;
    }

    @Override // com.quizlet.db.data.models.base.BaseDBModel, com.quizlet.db.data.models.base.DBModel
    public ModelIdentity<DBUserStudyable> getIdentity() {
        return new ModelBackedIdentity(this);
    }

    @JsonProperty(DBUserStudyableFields.Names.IS_ACTIVE)
    public Integer getIsActive() {
        return this.isActive;
    }

    @JsonProperty(DBUserStudyableFields.Names.IS_DISMISSED)
    public Boolean getIsDismissed() {
        return this.isDismissed;
    }

    @JsonProperty(DBUserStudyableFields.Names.LAST_STUDIED_TIMESTAMP)
    public Long getLastStudiedTimestamp() {
        return this.lastStudiedTimestamp;
    }

    @Override // com.quizlet.db.data.models.base.BaseDBModel, com.quizlet.db.data.models.base.DBModel
    @JsonIgnore
    public long getLocalId() {
        return this.localId;
    }

    @Override // com.quizlet.db.data.models.base.BaseDBModel, com.quizlet.db.data.models.base.DBModel
    public ModelType<DBUserStudyable> getModelType() {
        return Models.USER_STUDYABLE;
    }

    @JsonProperty(DBUserStudyableFields.Names.NOTIFICATION_STATUS)
    public Integer getNotificationStatus() {
        return this.notificationStatus;
    }

    @JsonProperty("personId")
    public Long getPersonId() {
        return this.personId;
    }

    public long getStartTimestampMilliSec() {
        return TimeUnit.SECONDS.toMillis(this.startTimestampSec.longValue());
    }

    @JsonProperty("startTimestamp")
    public Long getStartTimestampSec() {
        return this.startTimestampSec;
    }

    @JsonProperty(DBUserStudyableFields.Names.STUDYABLE_ID)
    public Long getStudyableId() {
        return this.studyableId;
    }

    @JsonIgnore
    public StudyableModel getStudyableModel() {
        return this.studyableModel;
    }

    @JsonProperty(DBUserStudyableFields.Names.STUDYABLE_TYPE)
    public Integer getStudyableType() {
        return this.studyableType;
    }

    @JsonProperty("timestamp")
    public Long getTimestamp() {
        return this.timestamp;
    }

    public boolean hasValidDueDate() {
        Long l = this.dueTimestampSec;
        return l != null && l.longValue() > 0;
    }

    public boolean notificationsEnabled() {
        return getNotificationStatus().intValue() == 1;
    }

    public void setDueTimestampSec(Long l) {
        this.dueTimestampSec = l;
    }

    public void setIsActive(Integer num) {
        this.isActive = num;
    }

    public void setIsDismissed(Boolean bool) {
        this.isDismissed = bool;
    }

    public void setLastStudiedTimestamp(Long l) {
        this.lastStudiedTimestamp = l;
    }

    @Override // com.quizlet.db.data.models.base.BaseDBModel, com.quizlet.db.data.models.base.DBModel
    public void setLocalId(long j) {
        this.localId = j;
    }

    public void setNotificationStatus(Integer num) {
        this.notificationStatus = num;
    }

    public void setPersonId(Long l) {
        this.personId = l;
    }

    public void setStartTimestampSec(Long l) {
        this.startTimestampSec = l;
    }

    public void setStudyableId(Long l) {
        this.studyableId = l;
    }

    public void setStudyableModel(StudyableModel studyableModel) {
        this.studyableModel = studyableModel;
    }

    public void setStudyableType(Integer num) {
        this.studyableType = num;
    }

    public void setTimestamp(Long l) {
        this.timestamp = l;
    }

    public DBUserStudyable(long j, long j2, int i, long j3) {
        this.personId = Long.valueOf(j);
        this.studyableId = Long.valueOf(j2);
        this.studyableType = Integer.valueOf(i);
        this.startTimestampSec = Long.valueOf(j3);
        this.notificationStatus = 0;
    }
}

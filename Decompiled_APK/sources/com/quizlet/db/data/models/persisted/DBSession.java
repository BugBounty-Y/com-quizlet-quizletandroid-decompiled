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
import com.quizlet.db.data.models.interfaces.FeedItem;
import com.quizlet.db.data.models.interfaces.StudyableModel;
import com.quizlet.db.data.models.persisted.base.ModelType;
import com.quizlet.db.data.models.persisted.base.Models;
import com.quizlet.db.data.models.persisted.fields.DBSessionFields;
import com.quizlet.db.data.models.persisted.fields.DBUserFields;
import com.quizlet.generated.enums.A1;
import com.quizlet.generated.enums.G1;

@JsonIgnoreProperties(ignoreUnknown = true)
@DatabaseTable(tableName = "session")
/* loaded from: classes2.dex */
public class DBSession extends BaseDBModel implements FeedItem {
    public static final String TABLE_NAME = "session";

    @DatabaseField(columnName = "id", id = true)
    private long id;

    @DatabaseField(columnName = DBSessionFields.Names.ITEM_ID)
    private long itemId;

    @DatabaseField(columnName = DBSessionFields.Names.ITEM_TYPE)
    private int itemType;

    @DatabaseField(columnName = "localGeneratedId")
    private long localId;
    private StudyableModel mStudyableModel;

    @DatabaseField(columnName = "personId")
    private long personId;

    @DatabaseField(columnName = DBSessionFields.Names.SELECTED_TERMS_ONLY)
    private boolean selectedTermsOnly;

    @DatabaseField(columnName = "startTimestamp")
    private long timestamp;

    @DatabaseField(columnName = "mode")
    private int type;

    @DatabaseField(columnName = DBSessionFields.Names.ENDED_TIMESTAMP)
    private long endedTimestamp = -1;

    @DatabaseField(columnName = DBSessionFields.Names.SCORE)
    private long score = 0;

    @DatabaseField
    private boolean hidden = false;

    public DBSession() {
    }

    @JsonIgnore
    public long getEndedTimestampMs() {
        return this.endedTimestamp;
    }

    @JsonProperty("endedTimestamp")
    public long getEndedTimestampSeconds() {
        return getEndedTimestampMs() / 1000;
    }

    @Override // com.quizlet.db.data.models.interfaces.FeedItem
    @JsonIgnore
    public Object getFeedId() {
        return Long.valueOf(getId());
    }

    @JsonProperty("hidden")
    public boolean getHidden() {
        return this.hidden;
    }

    @JsonIgnore
    public long getId() {
        return this.id;
    }

    @Override // com.quizlet.db.data.models.base.BaseDBModel, com.quizlet.db.data.models.base.DBModel
    public ModelIdentity<DBSession> getIdentity() {
        return new ModelBackedIdentity(this);
    }

    @JsonProperty(DBSessionFields.Names.ITEM_ID)
    public long getItemId() {
        return this.itemId;
    }

    @JsonProperty(DBSessionFields.Names.ITEM_TYPE)
    public int getItemType() {
        return this.itemType;
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

    public A1 getModeType() {
        int type = getType();
        A1.Companion.getClass();
        for (A1 a1 : A1.values()) {
            if (a1.a() == type) {
                return a1;
            }
        }
        return null;
    }

    @Override // com.quizlet.db.data.models.base.BaseDBModel, com.quizlet.db.data.models.base.DBModel
    public ModelType<DBSession> getModelType() {
        return Models.SESSION;
    }

    @JsonProperty("personId")
    public long getPersonId() {
        return this.personId;
    }

    @JsonProperty(DBSessionFields.Names.SCORE)
    public long getScore() {
        return this.score;
    }

    @JsonProperty(DBSessionFields.Names.SELECTED_TERMS_ONLY)
    public boolean getSelectedTermsOnly() {
        return this.selectedTermsOnly;
    }

    @Override // com.quizlet.db.data.models.interfaces.FeedItem
    public DBStudySet getSet() {
        StudyableModel studyableModel = getStudyableModel();
        if (studyableModel instanceof DBStudySet) {
            return (DBStudySet) studyableModel;
        }
        return null;
    }

    @Override // com.quizlet.db.data.models.interfaces.FeedItem
    public long getSetId() {
        if (getItemType() == G1.SET.b()) {
            return this.itemId;
        }
        return 0L;
    }

    @Override // com.quizlet.db.data.models.interfaces.FeedItem
    @JsonIgnore
    public long getSortTimestamp() {
        return getTimestamp();
    }

    @JsonIgnore
    public StudyableModel getStudyableModel() {
        return this.mStudyableModel;
    }

    @JsonProperty("timestamp")
    public long getTimestamp() {
        return getTimestampMs() / 1000;
    }

    @JsonIgnore
    public long getTimestampMs() {
        return this.timestamp;
    }

    @JsonProperty(DBUserFields.Names.USER_UPGRADE_TYPE)
    public int getType() {
        return this.type;
    }

    @JsonIgnore
    public boolean hasEnded() {
        return getEndedTimestampMs() > 0;
    }

    public void setEndedTimestampMs(long j) {
        this.endedTimestamp = j;
    }

    public void setEndedTimestampSeconds(long j) {
        setEndedTimestampMs(j * 1000);
    }

    public void setHidden(boolean z) {
        this.hidden = z;
    }

    public void setId(Long l) {
        this.id = l.longValue();
    }

    public void setItemId(long j) {
        this.itemId = j;
    }

    public void setItemType(int i) {
        this.itemType = i;
    }

    public void setJsonId(Long l) {
        this.id = l.longValue();
    }

    @Override // com.quizlet.db.data.models.base.BaseDBModel, com.quizlet.db.data.models.base.DBModel
    public void setLocalId(long j) {
        this.localId = j;
    }

    public void setPersonId(long j) {
        this.personId = j;
    }

    public void setScore(long j) {
        this.score = j;
    }

    public void setSelectedTermsOnly(boolean z) {
        this.selectedTermsOnly = z;
    }

    public void setStudyableModel(StudyableModel studyableModel) {
        this.mStudyableModel = studyableModel;
    }

    public void setTimestamp(long j) {
        setTimestampMs(j * 1000);
    }

    public void setTimestampMs(long j) {
        this.timestamp = j;
    }

    public void setType(int i) {
        this.type = i;
    }

    public DBSession(long j, long j2, G1 g1, A1 a1, boolean z, long j3) {
        setPersonId(j);
        setItemId(j2);
        setItemType(g1.b());
        setType(a1.a());
        setSelectedTermsOnly(z);
        setTimestampMs(j3);
    }
}

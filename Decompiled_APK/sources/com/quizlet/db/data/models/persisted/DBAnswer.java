package com.quizlet.db.data.models.persisted;

import com.bumptech.glide.b;
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
import com.quizlet.db.data.models.persisted.fields.DBAnswerFields;
import com.quizlet.db.data.models.persisted.fields.DBUserFields;
import com.quizlet.generated.enums.A1;
import com.quizlet.generated.enums.O1;

@JsonIgnoreProperties(ignoreUnknown = true)
@DatabaseTable(tableName = "answer")
/* loaded from: classes2.dex */
public class DBAnswer extends BaseDBModel {
    public static final String TABLE_NAME = "answer";

    @DatabaseField(columnName = "id", id = true)
    private long id;

    @DatabaseField(columnName = "localGeneratedId")
    private long localId;

    @DatabaseField(columnName = "personId")
    private long personId;

    @DatabaseField
    private int promptSide;

    @DatabaseField(columnName = DBAnswerFields.Names.SESSION_ID)
    private long sessionId;

    @DatabaseField(columnName = "setId")
    private long setId;

    @DatabaseField(columnName = "termId")
    private long termId;

    @DatabaseField(columnName = "mode")
    private long type = 0;

    @DatabaseField
    private int round = -1;

    @DatabaseField(columnName = DBAnswerFields.Names.CORRECTNESS)
    private int correctness = 0;

    @DatabaseField
    private long timestamp = -1;

    public DBAnswer() {
    }

    @JsonProperty(DBAnswerFields.Names.CORRECTNESS)
    public int getCorrectness() {
        return this.correctness;
    }

    @JsonIgnore
    public long getId() {
        return this.id;
    }

    @Override // com.quizlet.db.data.models.base.BaseDBModel, com.quizlet.db.data.models.base.DBModel
    public ModelIdentity<DBAnswer> getIdentity() {
        return new ModelBackedIdentity(this);
    }

    @Deprecated
    public boolean getIsCorrect() {
        return b.c(this.correctness);
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
    public ModelType<DBAnswer> getModelType() {
        return Models.ANSWER;
    }

    @JsonProperty("personId")
    public long getPersonId() {
        return this.personId;
    }

    @JsonProperty("promptSide")
    public int getPromptSide() {
        return this.promptSide;
    }

    @JsonProperty("questionType")
    public int getQuestionType() {
        return this.round;
    }

    @JsonProperty("round")
    public int getRound() {
        return this.round;
    }

    @JsonProperty(DBAnswerFields.Names.SESSION_ID)
    public long getSessionId() {
        return this.sessionId;
    }

    @JsonProperty("setId")
    public long getSetId() {
        return this.setId;
    }

    @JsonProperty("termId")
    public long getTermId() {
        return this.termId;
    }

    @JsonProperty("timestamp")
    public long getTimestamp() {
        return this.timestamp;
    }

    @JsonProperty(DBUserFields.Names.USER_UPGRADE_TYPE)
    public long getType() {
        return this.type;
    }

    public void setCorrectness(int i) {
        this.correctness = i;
    }

    public void setId(long j) {
        this.id = j;
    }

    public void setJsonId(Long l) {
        this.id = l == null ? 0L : l.longValue();
    }

    @Override // com.quizlet.db.data.models.base.BaseDBModel, com.quizlet.db.data.models.base.DBModel
    public void setLocalId(long j) {
        this.localId = j;
    }

    public void setPersonId(long j) {
        this.personId = j;
    }

    public void setPromptSide(int i) {
        this.promptSide = i;
    }

    public void setQuestionType(int i) {
        this.round = i;
    }

    public void setRound(int i) {
        this.round = i;
    }

    public void setSessionId(long j) {
        this.sessionId = j;
    }

    public void setSetId(long j) {
        this.setId = j;
    }

    public void setTermId(long j) {
        this.termId = j;
    }

    public void setTimestamp(long j) {
        this.timestamp = j;
    }

    public void setType(long j) {
        this.type = j;
    }

    public DBAnswer(long j, long j2, long j3, A1 a1, int i, int i2, long j4, O1 o1, long j5) {
        setSessionId(j);
        setSetId(j2);
        setTermId(j3);
        setType(a1.a());
        setRound(i);
        setCorrectness(i2);
        setPersonId(j4);
        setPromptSide(o1.a());
        setTimestamp(j5);
    }
}

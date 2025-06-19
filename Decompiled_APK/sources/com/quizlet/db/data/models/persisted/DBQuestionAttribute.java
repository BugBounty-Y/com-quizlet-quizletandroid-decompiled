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
import com.quizlet.db.data.models.persisted.fields.DBQuestionAttributeFields;

@JsonIgnoreProperties(ignoreUnknown = true)
@DatabaseTable(tableName = DBQuestionAttribute.TABLE_NAME)
/* loaded from: classes2.dex */
public class DBQuestionAttribute extends BaseDBModel {
    public static final String TABLE_NAME = "question_attribute";

    @DatabaseField(columnName = DBQuestionAttributeFields.Names.ANSWER_ID)
    private long answerId;

    @DatabaseField(columnName = "id", id = true)
    private long id;

    @DatabaseField(columnName = "localGeneratedId")
    private long localId;

    @DatabaseField(columnName = "personId")
    private long personId;

    @DatabaseField(columnName = DBQuestionAttributeFields.Names.QUESTION_SIDE)
    private int questionSide;

    @DatabaseField(columnName = "setId")
    private long setId;

    @DatabaseField(columnName = "termId")
    private Long termId;

    @DatabaseField(columnName = DBQuestionAttributeFields.Names.TERM_SIDE)
    private int termSide;

    @DatabaseField(columnName = "timestamp")
    private long timestamp;

    @JsonProperty(DBQuestionAttributeFields.Names.ANSWER_ID)
    public long getAnswerId() {
        return this.answerId;
    }

    @JsonIgnore
    public long getId() {
        return this.id;
    }

    @Override // com.quizlet.db.data.models.base.BaseDBModel, com.quizlet.db.data.models.base.DBModel
    public ModelIdentity<DBQuestionAttribute> getIdentity() {
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
    public ModelType<DBQuestionAttribute> getModelType() {
        return Models.QUESTION_ATTRIBUTE;
    }

    @JsonProperty("personId")
    public long getPersonId() {
        return this.personId;
    }

    @JsonProperty(DBQuestionAttributeFields.Names.QUESTION_SIDE)
    public int getQuestionSide() {
        return this.questionSide;
    }

    @JsonProperty("setId")
    public long getSetId() {
        return this.setId;
    }

    @JsonProperty("termId")
    public Long getTermId() {
        return this.termId;
    }

    @JsonProperty(DBQuestionAttributeFields.Names.TERM_SIDE)
    public int getTermSide() {
        return this.termSide;
    }

    @JsonProperty("timestamp")
    public long getTimestamp() {
        return this.timestamp;
    }

    public void setAnswerId(long j) {
        this.answerId = j;
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

    public void setPersonId(long j) {
        this.personId = j;
    }

    public void setQuestionSide(int i) {
        this.questionSide = i;
    }

    public void setSetId(long j) {
        this.setId = j;
    }

    public void setTermId(Long l) {
        this.termId = l;
    }

    public void setTermSide(int i) {
        this.termSide = i;
    }

    public void setTimestamp(long j) {
        this.timestamp = j;
    }
}

package com.quizlet.db.data.models.persisted;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.j256.ormlite.field.DatabaseField;
import com.j256.ormlite.table.DatabaseTable;
import com.quizlet.db.data.models.base.BaseDBModel;
import com.quizlet.db.data.models.identity.ModelBackedIdentity;
import com.quizlet.db.data.models.identity.ModelIdentity;
import com.quizlet.db.data.models.persisted.base.ModelType;
import com.quizlet.db.data.models.persisted.base.Models;

@JsonIgnoreProperties(ignoreUnknown = true)
@DatabaseTable(tableName = DBSelectedTerm.TABLE_NAME)
/* loaded from: classes2.dex */
public class DBSelectedTerm extends BaseDBModel {
    public static final String TABLE_NAME = "selected_term";

    @DatabaseField(columnName = "id", id = true)
    @Deprecated
    private long id;

    @DatabaseField(columnName = "localGeneratedId")
    private long localId;

    @DatabaseField(columnName = "personId", uniqueCombo = true)
    private long personId;

    @DatabaseField(columnName = "setId")
    private long setId;

    @DatabaseField
    private int source;

    @DatabaseField(columnName = "termId", uniqueCombo = true)
    private long termId;

    @DatabaseField
    private long timestamp;

    public DBSelectedTerm() {
    }

    @Override // com.quizlet.db.data.models.base.BaseDBModel, com.quizlet.db.data.models.base.DBModel
    public ModelIdentity<DBSelectedTerm> getIdentity() {
        return new ModelBackedIdentity(this);
    }

    @Override // com.quizlet.db.data.models.base.BaseDBModel, com.quizlet.db.data.models.base.DBModel
    public long getLocalId() {
        return this.localId;
    }

    @Override // com.quizlet.db.data.models.base.BaseDBModel, com.quizlet.db.data.models.base.DBModel
    public ModelType<DBSelectedTerm> getModelType() {
        return Models.SELECTED_TERM;
    }

    public long getPersonId() {
        return this.personId;
    }

    public long getSetId() {
        return this.setId;
    }

    public int getSource() {
        return this.source;
    }

    public long getTermId() {
        return this.termId;
    }

    public long getTimestamp() {
        return this.timestamp;
    }

    @Override // com.quizlet.db.data.models.base.BaseDBModel, com.quizlet.db.data.models.base.DBModel
    public void setLocalId(long j) {
        this.localId = j;
        this.id = j;
    }

    public void setPersonId(long j) {
        this.personId = j;
    }

    public void setSetId(long j) {
        this.setId = j;
    }

    public void setSource(int i) {
        this.source = i;
    }

    public void setTermId(Long l) {
        this.termId = l.longValue();
    }

    public void setTimestamp(long j) {
        this.timestamp = j;
    }

    public DBSelectedTerm(long j, long j2, long j3, long j4, int i) {
        this.personId = j;
        this.setId = j2;
        this.termId = j3;
        this.timestamp = j4;
        this.source = i;
    }
}

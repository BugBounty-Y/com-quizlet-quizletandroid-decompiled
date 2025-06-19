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
import com.quizlet.db.data.models.persisted.fields.DBDiagramShapeFields;

@JsonIgnoreProperties(ignoreUnknown = true)
@DatabaseTable(tableName = DBDiagramShape.TABLE_NAME)
/* loaded from: classes2.dex */
public class DBDiagramShape extends BaseDBModel {
    public static final String TABLE_NAME = "diagramShape";

    @DatabaseField(columnName = "id", id = true)
    private long id;

    @DatabaseField(columnName = "localGeneratedId")
    private long localId;

    @DatabaseField(columnName = "setId")
    private long setId;

    @DatabaseField(columnName = DBDiagramShapeFields.Names.SHAPE)
    private String shape;

    @DatabaseField(columnName = "termId")
    private long termId;

    @DatabaseField(columnName = "timestamp")
    private long timestamp;

    @JsonIgnore
    public long getId() {
        return this.id;
    }

    @Override // com.quizlet.db.data.models.base.BaseDBModel, com.quizlet.db.data.models.base.DBModel
    public ModelIdentity<DBDiagramShape> getIdentity() {
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
    public ModelType<DBDiagramShape> getModelType() {
        return Models.DIAGRAM_SHAPE;
    }

    public long getSetId() {
        return this.setId;
    }

    @JsonProperty(DBDiagramShapeFields.Names.SHAPE)
    public String getShape() {
        return this.shape;
    }

    public long getTermId() {
        return this.termId;
    }

    @JsonProperty("timestamp")
    public long getTimestamp() {
        return this.timestamp;
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

    @JsonProperty("setId")
    public void setSetId(long j) {
        this.setId = j;
    }

    public void setShape(String str) {
        this.shape = str;
    }

    @JsonProperty("termId")
    public void setTermId(long j) {
        this.termId = j;
    }

    public void setTimestamp(long j) {
        this.timestamp = j;
    }
}

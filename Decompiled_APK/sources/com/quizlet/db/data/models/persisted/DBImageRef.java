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
import com.quizlet.db.data.models.persisted.fields.DBImageRefFields;

@JsonIgnoreProperties(ignoreUnknown = true)
@DatabaseTable(tableName = DBImageRef.TABLE_NAME)
/* loaded from: classes2.dex */
public class DBImageRef extends BaseDBModel {
    public static final String TABLE_NAME = "imageRef";

    @DatabaseField(columnName = "id", id = true)
    private long id;

    @JsonIgnore
    private DBImage image;

    @DatabaseField(columnName = DBImageRefFields.Names.IMAGE_ID)
    private long imageId;

    @DatabaseField(columnName = DBImageRefFields.Names.IMAGE_TYPE)
    private int imageType;

    @DatabaseField(columnName = "localGeneratedId")
    private long localId;

    @DatabaseField(columnName = DBImageRefFields.Names.MODEL_ID)
    private long modelId;

    @DatabaseField(columnName = DBImageRefFields.Names.MODEL_TYPE)
    private int modelType;

    @DatabaseField(columnName = "timestamp")
    private long timestamp;

    @JsonProperty(DBImageRefFields.Names.MODEL_TYPE)
    public int getApiModelType() {
        return this.modelType;
    }

    @JsonIgnore
    public long getId() {
        return this.id;
    }

    @Override // com.quizlet.db.data.models.base.BaseDBModel, com.quizlet.db.data.models.base.DBModel
    public ModelIdentity<DBImageRef> getIdentity() {
        return new ModelBackedIdentity(this);
    }

    @JsonIgnore
    public DBImage getImage() {
        return this.image;
    }

    @JsonProperty(DBImageRefFields.Names.IMAGE_ID)
    public long getImageId() {
        return this.imageId;
    }

    @JsonProperty(DBImageRefFields.Names.IMAGE_TYPE)
    public int getImageType() {
        return this.imageType;
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

    @JsonProperty(DBImageRefFields.Names.MODEL_ID)
    public long getModelId() {
        return this.modelId;
    }

    @Override // com.quizlet.db.data.models.base.BaseDBModel, com.quizlet.db.data.models.base.DBModel
    public ModelType<DBImageRef> getModelType() {
        return Models.IMAGE_REF;
    }

    @JsonProperty("timestamp")
    public long getTimestamp() {
        return this.timestamp;
    }

    public void setApiModelType(int i) {
        this.modelType = i;
    }

    public void setId(long j) {
        this.id = j;
    }

    @JsonIgnore
    public void setImage(DBImage dBImage) {
        this.image = dBImage;
    }

    public void setImageId(long j) {
        this.imageId = j;
    }

    public void setImageType(int i) {
        this.imageType = i;
    }

    public void setJsonId(Long l) {
        this.id = l.longValue();
    }

    @Override // com.quizlet.db.data.models.base.BaseDBModel, com.quizlet.db.data.models.base.DBModel
    public void setLocalId(long j) {
        this.localId = j;
    }

    public void setModelId(long j) {
        this.modelId = j;
    }

    public void setTimestamp(long j) {
        this.timestamp = j;
    }
}

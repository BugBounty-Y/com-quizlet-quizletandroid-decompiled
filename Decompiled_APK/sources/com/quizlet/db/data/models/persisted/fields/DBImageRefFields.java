package com.quizlet.db.data.models.persisted.fields;

import com.quizlet.db.data.models.base.ColumnField;
import com.quizlet.db.data.models.base.ModelField;
import com.quizlet.db.data.models.persisted.DBImage;
import com.quizlet.db.data.models.persisted.DBImageRef;
import com.quizlet.db.data.models.persisted.base.ModelType;
import com.quizlet.db.data.models.persisted.base.Models;
import com.quizlet.db.data.orm.Relationship;
import com.quizlet.db.data.orm.SingleRelationship;

/* loaded from: classes2.dex */
public class DBImageRefFields {
    public static final ModelField<DBImageRef, Long> ID;
    public static final Relationship<DBImageRef, DBImage> IMAGE;
    public static final ModelField<DBImageRef, Long> LOCAL_ID;
    public static final ModelField<DBImageRef, Long> MODEL_ID;

    public static class Names {
        public static final String DIRTY = "dirty";
        public static final String ID = "id";
        public static final String IMAGE_ID = "imageId";
        public static final String IMAGE_TYPE = "imageType";
        public static final String IS_DELETED = "isDeleted";
        public static final String LAST_MODIFIED = "lastModified";
        public static final String LOCAL_ID = "localGeneratedId";
        public static final String MODEL_ID = "modelId";
        public static final String MODEL_TYPE = "modelType";
        public static final String TIMESTAMP = "timestamp";
    }

    static {
        ModelType<DBImageRef> modelType = Models.IMAGE_REF;
        LOCAL_ID = new ColumnField<DBImageRef, Long>(modelType, "localGeneratedId") { // from class: com.quizlet.db.data.models.persisted.fields.DBImageRefFields.1
            @Override // com.quizlet.db.data.models.base.ModelField
            public Long getValue(DBImageRef dBImageRef) {
                return Long.valueOf(dBImageRef.getLocalId());
            }

            @Override // com.quizlet.db.data.models.base.ModelField
            public void setValue(DBImageRef dBImageRef, Long l) {
                dBImageRef.setLocalId(l.longValue());
            }
        };
        ID = new ColumnField<DBImageRef, Long>(modelType, "id") { // from class: com.quizlet.db.data.models.persisted.fields.DBImageRefFields.2
            @Override // com.quizlet.db.data.models.base.ModelField
            public Long getValue(DBImageRef dBImageRef) {
                return Long.valueOf(dBImageRef.getId());
            }

            @Override // com.quizlet.db.data.models.base.ModelField
            public void setValue(DBImageRef dBImageRef, Long l) {
                dBImageRef.setId(l.longValue());
            }
        };
        MODEL_ID = new ColumnField<DBImageRef, Long>(modelType, Names.MODEL_ID) { // from class: com.quizlet.db.data.models.persisted.fields.DBImageRefFields.3
            @Override // com.quizlet.db.data.models.base.ModelField
            public Long getValue(DBImageRef dBImageRef) {
                return Long.valueOf(dBImageRef.getModelId());
            }

            @Override // com.quizlet.db.data.models.base.ModelField
            public void setValue(DBImageRef dBImageRef, Long l) {
                dBImageRef.setModelId(l.longValue());
            }
        };
        IMAGE = new SingleRelationship<DBImageRef, DBImage>(modelType, Names.IMAGE_ID, Models.IMAGE) { // from class: com.quizlet.db.data.models.persisted.fields.DBImageRefFields.4
            @Override // com.quizlet.db.data.orm.Relationship
            public String getApiAssociationName() {
                return "image";
            }

            @Override // com.quizlet.db.data.orm.Relationship
            public DBImage getModel(DBImageRef dBImageRef) {
                return dBImageRef.getImage();
            }

            @Override // com.quizlet.db.data.models.base.ModelField
            public Long getValue(DBImageRef dBImageRef) {
                return Long.valueOf(dBImageRef.getImageId());
            }

            @Override // com.quizlet.db.data.orm.Relationship
            public void setModel(DBImageRef dBImageRef, DBImage dBImage) {
                dBImageRef.setImage(dBImage);
            }

            @Override // com.quizlet.db.data.models.base.ModelField
            public void setValue(DBImageRef dBImageRef, Long l) {
                dBImageRef.setImageId(l.longValue());
            }
        };
    }
}

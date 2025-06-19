package com.quizlet.db.data.models.persisted.fields;

import com.quizlet.db.data.models.base.ColumnField;
import com.quizlet.db.data.models.base.ModelField;
import com.quizlet.db.data.models.persisted.DBDiagramShape;
import com.quizlet.db.data.models.persisted.DBStudySet;
import com.quizlet.db.data.models.persisted.DBTerm;
import com.quizlet.db.data.models.persisted.base.ModelType;
import com.quizlet.db.data.models.persisted.base.Models;
import com.quizlet.db.data.orm.NoModelRelationship;
import com.quizlet.db.data.orm.Relationship;

/* loaded from: classes2.dex */
public class DBDiagramShapeFields {
    public static final ModelField<DBDiagramShape, Long> ID;
    public static final ModelField<DBDiagramShape, Long> LOCAL_ID;
    public static final Relationship<DBDiagramShape, DBStudySet> SET_ID;
    public static final Relationship<DBDiagramShape, DBTerm> TERM_ID;

    public static class Names {
        public static final String DIRTY = "dirty";
        public static final String ID = "id";
        public static final String IS_DELETED = "isDeleted";
        public static final String LAST_MODIFIED = "lastModified";
        public static final String LOCAL_ID = "localGeneratedId";
        public static final String SET_ID = "setId";
        public static final String SHAPE = "shape";
        public static final String TERM_ID = "termId";
        public static final String TIMESTAMP = "timestamp";
    }

    static {
        ModelType<DBDiagramShape> modelType = Models.DIAGRAM_SHAPE;
        LOCAL_ID = new ColumnField<DBDiagramShape, Long>(modelType, "localGeneratedId") { // from class: com.quizlet.db.data.models.persisted.fields.DBDiagramShapeFields.1
            @Override // com.quizlet.db.data.models.base.ModelField
            public Long getValue(DBDiagramShape dBDiagramShape) {
                return Long.valueOf(dBDiagramShape.getLocalId());
            }

            @Override // com.quizlet.db.data.models.base.ModelField
            public void setValue(DBDiagramShape dBDiagramShape, Long l) {
                dBDiagramShape.setLocalId(l.longValue());
            }
        };
        ID = new ColumnField<DBDiagramShape, Long>(modelType, "id") { // from class: com.quizlet.db.data.models.persisted.fields.DBDiagramShapeFields.2
            @Override // com.quizlet.db.data.models.base.ModelField
            public Long getValue(DBDiagramShape dBDiagramShape) {
                return Long.valueOf(dBDiagramShape.getId());
            }

            @Override // com.quizlet.db.data.models.base.ModelField
            public void setValue(DBDiagramShape dBDiagramShape, Long l) {
                dBDiagramShape.setId(l.longValue());
            }
        };
        SET_ID = new NoModelRelationship<DBDiagramShape, DBStudySet>(modelType, "setId", Models.STUDY_SET) { // from class: com.quizlet.db.data.models.persisted.fields.DBDiagramShapeFields.3
            @Override // com.quizlet.db.data.orm.Relationship
            public String getApiAssociationName() {
                return "set";
            }

            @Override // com.quizlet.db.data.models.base.ModelField
            public Long getValue(DBDiagramShape dBDiagramShape) {
                return Long.valueOf(dBDiagramShape.getSetId());
            }

            @Override // com.quizlet.db.data.models.base.ModelField
            public void setValue(DBDiagramShape dBDiagramShape, Long l) {
                dBDiagramShape.setSetId(l.longValue());
            }
        };
        TERM_ID = new NoModelRelationship<DBDiagramShape, DBTerm>(modelType, "termId", Models.TERM) { // from class: com.quizlet.db.data.models.persisted.fields.DBDiagramShapeFields.4
            @Override // com.quizlet.db.data.orm.Relationship
            public String getApiAssociationName() {
                return "term";
            }

            @Override // com.quizlet.db.data.models.base.ModelField
            public Long getValue(DBDiagramShape dBDiagramShape) {
                return Long.valueOf(dBDiagramShape.getTermId());
            }

            @Override // com.quizlet.db.data.models.base.ModelField
            public void setValue(DBDiagramShape dBDiagramShape, Long l) {
                dBDiagramShape.setTermId(l.longValue());
            }
        };
    }
}

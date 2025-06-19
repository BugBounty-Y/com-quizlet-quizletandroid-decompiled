package com.quizlet.db.data.models.persisted.fields;

import com.quizlet.db.data.models.base.AssociationNames;
import com.quizlet.db.data.models.base.ColumnField;
import com.quizlet.db.data.models.base.ModelField;
import com.quizlet.db.data.models.persisted.DBFolder;
import com.quizlet.db.data.models.persisted.DBUser;
import com.quizlet.db.data.models.persisted.base.ModelType;
import com.quizlet.db.data.models.persisted.base.Models;
import com.quizlet.db.data.orm.Relationship;
import com.quizlet.db.data.orm.SingleRelationship;

/* loaded from: classes2.dex */
public class DBFolderFields {
    public static final ModelField<DBFolder, Long> ID;
    public static final ModelField<DBFolder, Long> LOCAL_ID;
    public static final Relationship<DBFolder, DBUser> PERSON;

    public static final class Names {
        public static final String ID = "id";
        public static final String IS_COURSE_POWERED = "isCoursePowered";
        public static final String LOCAL_ID = "localGeneratedId";
        public static final String NUM_SETS = "_numSets";
        public static final String PERSON_ID = "personId";
        public static final String QPF_GENERATION_METHOD = "qpfGenerationMethod";
        public static final String SCHOOL_COURSE_DESCRIPTION = "dSchoolCourseDescription";
        public static final String WEB_URL = "_webUrl";
    }

    static {
        ModelType<DBFolder> modelType = Models.FOLDER;
        LOCAL_ID = new ColumnField<DBFolder, Long>(modelType, "localGeneratedId") { // from class: com.quizlet.db.data.models.persisted.fields.DBFolderFields.1
            @Override // com.quizlet.db.data.models.base.ModelField
            public Long getValue(DBFolder dBFolder) {
                return Long.valueOf(dBFolder.getLocalId());
            }

            @Override // com.quizlet.db.data.models.base.ModelField
            public void setValue(DBFolder dBFolder, Long l) {
                dBFolder.setLocalId(l.longValue());
            }
        };
        ID = new ColumnField<DBFolder, Long>(modelType, "id") { // from class: com.quizlet.db.data.models.persisted.fields.DBFolderFields.2
            @Override // com.quizlet.db.data.models.base.ModelField
            public Long getValue(DBFolder dBFolder) {
                return Long.valueOf(dBFolder.getId());
            }

            @Override // com.quizlet.db.data.models.base.ModelField
            public void setValue(DBFolder dBFolder, Long l) {
                dBFolder.setId(l.longValue());
            }
        };
        PERSON = new SingleRelationship<DBFolder, DBUser>(modelType, "personId", Models.USER) { // from class: com.quizlet.db.data.models.persisted.fields.DBFolderFields.3
            @Override // com.quizlet.db.data.orm.Relationship
            public String getApiAssociationName() {
                return AssociationNames.PERSON;
            }

            @Override // com.quizlet.db.data.orm.Relationship
            public DBUser getModel(DBFolder dBFolder) {
                return dBFolder.getPerson();
            }

            @Override // com.quizlet.db.data.models.base.ModelField
            public Long getValue(DBFolder dBFolder) {
                return Long.valueOf(dBFolder.getPersonId());
            }

            @Override // com.quizlet.db.data.orm.Relationship
            public void setModel(DBFolder dBFolder, DBUser dBUser) {
                dBFolder.setPerson(dBUser);
            }

            @Override // com.quizlet.db.data.models.base.ModelField
            public void setValue(DBFolder dBFolder, Long l) {
                dBFolder.setPersonId(l.longValue());
            }
        };
    }
}

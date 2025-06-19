package com.quizlet.db.data.models.persisted.fields;

import com.quizlet.db.data.models.base.AssociationNames;
import com.quizlet.db.data.models.base.ColumnField;
import com.quizlet.db.data.models.base.ModelField;
import com.quizlet.db.data.models.persisted.DBStudySet;
import com.quizlet.db.data.models.persisted.DBUser;
import com.quizlet.db.data.models.persisted.base.ModelType;
import com.quizlet.db.data.models.persisted.base.Models;
import com.quizlet.db.data.orm.Relationship;
import com.quizlet.db.data.orm.SingleRelationship;

/* loaded from: classes2.dex */
public class DBStudySetFields {
    public static final Relationship<DBStudySet, DBUser> CREATOR;
    public static final ModelField<DBStudySet, Long> ID;
    public static final ModelField<DBStudySet, Long> LOCAL_ID;
    public static final ModelField<DBStudySet, Long> NUM_TERMS;

    public static final class Names {
        public static final String ACCESS_CODE_PREFIX = "accessCodePrefix";
        public static final String ACCESS_TYPE = "accessType";
        public static final String CREATOR_ID = "creatorId";
        public static final String DEFINITION_LANGUAGE = "langDefinitions";
        public static final String HAS_DIAGRAMS = "hasDiagrams";
        public static final String ID = "id";
        public static final String LOCAL_ID = "localGeneratedId";
        public static final String MCQ_COUNT = "mcqCount";
        public static final String NUM_TERMS = "termCount";
        public static final String PASSWORD = "password";
        public static final String PUBLISHED_TIMESTAMP = "publishedTimestamp";
        public static final String READY_TO_CREATE = "readyToCreate";
        public static final String THUMBNAIL_URL = "_thumbnailUrl";
        public static final String TIMESTAMP = "createdDate";
        public static final String TITLE = "title";
        public static final String WEB_URL = "_webUrl";
        public static final String WORD_LANGUAGE = "langTerms";
    }

    static {
        ModelType<DBStudySet> modelType = Models.STUDY_SET;
        LOCAL_ID = new ColumnField<DBStudySet, Long>(modelType, "localGeneratedId") { // from class: com.quizlet.db.data.models.persisted.fields.DBStudySetFields.1
            @Override // com.quizlet.db.data.models.base.ModelField
            public Long getValue(DBStudySet dBStudySet) {
                return Long.valueOf(dBStudySet.getLocalId());
            }

            @Override // com.quizlet.db.data.models.base.ModelField
            public void setValue(DBStudySet dBStudySet, Long l) {
                dBStudySet.setLocalId(l.longValue());
            }
        };
        ID = new ColumnField<DBStudySet, Long>(modelType, "id") { // from class: com.quizlet.db.data.models.persisted.fields.DBStudySetFields.2
            @Override // com.quizlet.db.data.models.base.ModelField
            public Long getValue(DBStudySet dBStudySet) {
                return Long.valueOf(dBStudySet.getId());
            }

            @Override // com.quizlet.db.data.models.base.ModelField
            public void setValue(DBStudySet dBStudySet, Long l) {
                dBStudySet.setId(l.longValue());
            }
        };
        NUM_TERMS = new ColumnField<DBStudySet, Long>(modelType, Names.NUM_TERMS) { // from class: com.quizlet.db.data.models.persisted.fields.DBStudySetFields.3
            @Override // com.quizlet.db.data.models.base.ModelField
            public Long getValue(DBStudySet dBStudySet) {
                return Long.valueOf(dBStudySet.getNumTerms());
            }

            @Override // com.quizlet.db.data.models.base.ModelField
            public void setValue(DBStudySet dBStudySet, Long l) {
                dBStudySet.setNumTerms(l.intValue());
            }
        };
        CREATOR = new SingleRelationship<DBStudySet, DBUser>(modelType, "creatorId", Models.USER) { // from class: com.quizlet.db.data.models.persisted.fields.DBStudySetFields.4
            @Override // com.quizlet.db.data.orm.Relationship
            public String getApiAssociationName() {
                return AssociationNames.CREATOR;
            }

            @Override // com.quizlet.db.data.orm.Relationship
            public DBUser getModel(DBStudySet dBStudySet) {
                return dBStudySet.getCreator();
            }

            @Override // com.quizlet.db.data.models.base.ModelField
            public Long getValue(DBStudySet dBStudySet) {
                return Long.valueOf(dBStudySet.getCreatorId());
            }

            @Override // com.quizlet.db.data.orm.Relationship
            public void setModel(DBStudySet dBStudySet, DBUser dBUser) {
                dBStudySet.setCreator(dBUser);
            }

            @Override // com.quizlet.db.data.models.base.ModelField
            public void setValue(DBStudySet dBStudySet, Long l) {
                dBStudySet.setCreatorId(l.longValue());
            }
        };
    }
}

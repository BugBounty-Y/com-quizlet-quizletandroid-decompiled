package com.quizlet.db.data.models.persisted.fields;

import com.quizlet.db.data.models.base.ColumnField;
import com.quizlet.db.data.models.base.ModelField;
import com.quizlet.db.data.models.persisted.DBAnswer;
import com.quizlet.db.data.models.persisted.DBQuestionAttribute;
import com.quizlet.db.data.models.persisted.DBStudySet;
import com.quizlet.db.data.models.persisted.DBTerm;
import com.quizlet.db.data.models.persisted.DBUser;
import com.quizlet.db.data.models.persisted.base.ModelType;
import com.quizlet.db.data.models.persisted.base.Models;
import com.quizlet.db.data.orm.NoModelRelationship;
import com.quizlet.db.data.orm.Relationship;

/* loaded from: classes2.dex */
public class DBQuestionAttributeFields {
    public static final Relationship<DBQuestionAttribute, DBAnswer> ANSWER_ID;
    public static final ModelField<DBQuestionAttribute, Long> ID;
    public static final ModelField<DBQuestionAttribute, Long> LOCAL_ID;
    public static final Relationship<DBQuestionAttribute, DBUser> PERSON_ID;
    public static final Relationship<DBQuestionAttribute, DBStudySet> SET_ID;
    public static final Relationship<DBQuestionAttribute, DBTerm> TERM_ID;

    public static final class Names {
        public static final String ANSWER_ID = "answerId";
        public static final String ID = "id";
        public static final String LOCAL_ID = "localGeneratedId";
        public static final String PERSON_ID = "personId";
        public static final String QUESTION_SIDE = "questionSide";
        public static final String SET_ID = "setId";
        public static final String TERM_ID = "termId";
        public static final String TERM_SIDE = "termSide";
        public static final String TIMESTAMP = "timestamp";
    }

    static {
        ModelType<DBQuestionAttribute> modelType = Models.QUESTION_ATTRIBUTE;
        LOCAL_ID = new ColumnField<DBQuestionAttribute, Long>(modelType, "localGeneratedId") { // from class: com.quizlet.db.data.models.persisted.fields.DBQuestionAttributeFields.1
            @Override // com.quizlet.db.data.models.base.ModelField
            public Long getValue(DBQuestionAttribute dBQuestionAttribute) {
                return Long.valueOf(dBQuestionAttribute.getLocalId());
            }

            @Override // com.quizlet.db.data.models.base.ModelField
            public void setValue(DBQuestionAttribute dBQuestionAttribute, Long l) {
                dBQuestionAttribute.setLocalId(l.longValue());
            }
        };
        ID = new ColumnField<DBQuestionAttribute, Long>(modelType, "id") { // from class: com.quizlet.db.data.models.persisted.fields.DBQuestionAttributeFields.2
            @Override // com.quizlet.db.data.models.base.ModelField
            public Long getValue(DBQuestionAttribute dBQuestionAttribute) {
                return Long.valueOf(dBQuestionAttribute.getId());
            }

            @Override // com.quizlet.db.data.models.base.ModelField
            public void setValue(DBQuestionAttribute dBQuestionAttribute, Long l) {
                dBQuestionAttribute.setId(l.longValue());
            }
        };
        ANSWER_ID = new NoModelRelationship<DBQuestionAttribute, DBAnswer>(modelType, Names.ANSWER_ID, Models.ANSWER) { // from class: com.quizlet.db.data.models.persisted.fields.DBQuestionAttributeFields.3
            @Override // com.quizlet.db.data.orm.Relationship
            public String getApiAssociationName() {
                return "answer";
            }

            @Override // com.quizlet.db.data.models.base.ModelField
            public Long getValue(DBQuestionAttribute dBQuestionAttribute) {
                return Long.valueOf(dBQuestionAttribute.getAnswerId());
            }

            @Override // com.quizlet.db.data.models.base.ModelField
            public void setValue(DBQuestionAttribute dBQuestionAttribute, Long l) {
                dBQuestionAttribute.setAnswerId(l.longValue());
            }
        };
        PERSON_ID = new NoModelRelationship<DBQuestionAttribute, DBUser>(modelType, "personId", Models.USER) { // from class: com.quizlet.db.data.models.persisted.fields.DBQuestionAttributeFields.4
            @Override // com.quizlet.db.data.orm.Relationship
            public String getApiAssociationName() {
                return "user";
            }

            @Override // com.quizlet.db.data.models.base.ModelField
            public Long getValue(DBQuestionAttribute dBQuestionAttribute) {
                return Long.valueOf(dBQuestionAttribute.getPersonId());
            }

            @Override // com.quizlet.db.data.models.base.ModelField
            public void setValue(DBQuestionAttribute dBQuestionAttribute, Long l) {
                dBQuestionAttribute.setPersonId(l.longValue());
            }
        };
        SET_ID = new NoModelRelationship<DBQuestionAttribute, DBStudySet>(modelType, "setId", Models.STUDY_SET) { // from class: com.quizlet.db.data.models.persisted.fields.DBQuestionAttributeFields.5
            @Override // com.quizlet.db.data.orm.Relationship
            public String getApiAssociationName() {
                return "set";
            }

            @Override // com.quizlet.db.data.models.base.ModelField
            public Long getValue(DBQuestionAttribute dBQuestionAttribute) {
                return Long.valueOf(dBQuestionAttribute.getSetId());
            }

            @Override // com.quizlet.db.data.models.base.ModelField
            public void setValue(DBQuestionAttribute dBQuestionAttribute, Long l) {
                dBQuestionAttribute.setSetId(l.longValue());
            }
        };
        TERM_ID = new NoModelRelationship<DBQuestionAttribute, DBTerm>(modelType, "termId", Models.TERM) { // from class: com.quizlet.db.data.models.persisted.fields.DBQuestionAttributeFields.6
            @Override // com.quizlet.db.data.orm.Relationship
            public String getApiAssociationName() {
                return "term";
            }

            @Override // com.quizlet.db.data.models.base.ModelField
            public Long getValue(DBQuestionAttribute dBQuestionAttribute) {
                return dBQuestionAttribute.getTermId();
            }

            @Override // com.quizlet.db.data.models.base.ModelField
            public void setValue(DBQuestionAttribute dBQuestionAttribute, Long l) {
                dBQuestionAttribute.setTermId(l);
            }
        };
    }
}

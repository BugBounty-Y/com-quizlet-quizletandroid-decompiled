package com.quizlet.db.data.models.persisted.fields;

import com.quizlet.db.data.models.base.ColumnField;
import com.quizlet.db.data.models.base.ModelField;
import com.quizlet.db.data.models.persisted.DBAnswer;
import com.quizlet.db.data.models.persisted.DBSession;
import com.quizlet.db.data.models.persisted.DBStudySet;
import com.quizlet.db.data.models.persisted.DBTerm;
import com.quizlet.db.data.models.persisted.DBUser;
import com.quizlet.db.data.models.persisted.base.ModelType;
import com.quizlet.db.data.models.persisted.base.Models;
import com.quizlet.db.data.models.persisted.fields.DBUserFields;
import com.quizlet.db.data.orm.NoModelRelationship;
import com.quizlet.db.data.orm.Relationship;

/* loaded from: classes2.dex */
public class DBAnswerFields {
    public static final ModelField<DBAnswer, Long> ID;
    public static final ModelField<DBAnswer, Long> LOCAL_ID;
    public static final ModelField<DBAnswer, Long> MODE_TYPE;
    public static final Relationship<DBAnswer, DBUser> PERSON;
    public static final Relationship<DBAnswer, DBSession> SESSION;
    public static final Relationship<DBAnswer, DBStudySet> SET;
    public static final Relationship<DBAnswer, DBTerm> TERM;

    public static final class Names {
        public static final String CORRECTNESS = "correctness";
        public static final String ID = "id";
        public static final String IS_CORRECT = "isCorrect";
        public static final String LOCAL_ID = "localGeneratedId";
        public static final String MODE_TYPE = "mode";
        public static final String PERSON_ID = "personId";
        public static final String SESSION_ID = "sessionId";
        public static final String SET_ID = "setId";
        public static final String TERM_ID = "termId";
    }

    static {
        ModelType<DBAnswer> modelType = Models.ANSWER;
        LOCAL_ID = new ColumnField<DBAnswer, Long>(modelType, "localGeneratedId") { // from class: com.quizlet.db.data.models.persisted.fields.DBAnswerFields.1
            @Override // com.quizlet.db.data.models.base.ModelField
            public Long getValue(DBAnswer dBAnswer) {
                return Long.valueOf(dBAnswer.getLocalId());
            }

            @Override // com.quizlet.db.data.models.base.ModelField
            public void setValue(DBAnswer dBAnswer, Long l) {
                dBAnswer.setLocalId(l.longValue());
            }
        };
        ID = new ColumnField<DBAnswer, Long>(modelType, "id") { // from class: com.quizlet.db.data.models.persisted.fields.DBAnswerFields.2
            @Override // com.quizlet.db.data.models.base.ModelField
            public Long getValue(DBAnswer dBAnswer) {
                return Long.valueOf(dBAnswer.getId());
            }

            @Override // com.quizlet.db.data.models.base.ModelField
            public void setValue(DBAnswer dBAnswer, Long l) {
                dBAnswer.setId(l.longValue());
            }
        };
        MODE_TYPE = new ColumnField<DBAnswer, Long>(modelType, "mode") { // from class: com.quizlet.db.data.models.persisted.fields.DBAnswerFields.3
            @Override // com.quizlet.db.data.models.base.ModelField
            public String getAPIFieldName() {
                return DBUserFields.Names.USER_UPGRADE_TYPE;
            }

            @Override // com.quizlet.db.data.models.base.ModelField
            public Long getValue(DBAnswer dBAnswer) {
                return Long.valueOf(dBAnswer.getType());
            }

            @Override // com.quizlet.db.data.models.base.ModelField
            public void setValue(DBAnswer dBAnswer, Long l) {
                dBAnswer.setType(l.longValue());
            }
        };
        TERM = new NoModelRelationship<DBAnswer, DBTerm>(modelType, "termId", Models.TERM) { // from class: com.quizlet.db.data.models.persisted.fields.DBAnswerFields.4
            @Override // com.quizlet.db.data.orm.Relationship
            public String getApiAssociationName() {
                return "term";
            }

            @Override // com.quizlet.db.data.models.base.ModelField
            public Long getValue(DBAnswer dBAnswer) {
                return Long.valueOf(dBAnswer.getTermId());
            }

            @Override // com.quizlet.db.data.models.base.ModelField
            public void setValue(DBAnswer dBAnswer, Long l) {
                dBAnswer.setTermId(l.longValue());
            }
        };
        SESSION = new NoModelRelationship<DBAnswer, DBSession>(modelType, Names.SESSION_ID, Models.SESSION) { // from class: com.quizlet.db.data.models.persisted.fields.DBAnswerFields.5
            @Override // com.quizlet.db.data.orm.Relationship
            public String getApiAssociationName() {
                return "session";
            }

            @Override // com.quizlet.db.data.models.base.ModelField
            public Long getValue(DBAnswer dBAnswer) {
                return Long.valueOf(dBAnswer.getSessionId());
            }

            @Override // com.quizlet.db.data.models.base.ModelField
            public void setValue(DBAnswer dBAnswer, Long l) {
                dBAnswer.setSessionId(l.longValue());
            }
        };
        SET = new NoModelRelationship<DBAnswer, DBStudySet>(modelType, "setId", Models.STUDY_SET) { // from class: com.quizlet.db.data.models.persisted.fields.DBAnswerFields.6
            @Override // com.quizlet.db.data.orm.Relationship
            public String getApiAssociationName() {
                return "set";
            }

            @Override // com.quizlet.db.data.models.base.ModelField
            public Long getValue(DBAnswer dBAnswer) {
                return Long.valueOf(dBAnswer.getSetId());
            }

            @Override // com.quizlet.db.data.models.base.ModelField
            public void setValue(DBAnswer dBAnswer, Long l) {
                dBAnswer.setSetId(l.longValue());
            }
        };
        PERSON = new NoModelRelationship<DBAnswer, DBUser>(modelType, "personId", Models.USER) { // from class: com.quizlet.db.data.models.persisted.fields.DBAnswerFields.7
            @Override // com.quizlet.db.data.orm.Relationship
            public String getApiAssociationName() {
                return "user";
            }

            @Override // com.quizlet.db.data.models.base.ModelField
            public Long getValue(DBAnswer dBAnswer) {
                return Long.valueOf(dBAnswer.getPersonId());
            }

            @Override // com.quizlet.db.data.models.base.ModelField
            public void setValue(DBAnswer dBAnswer, Long l) {
                dBAnswer.setPersonId(l.longValue());
            }
        };
    }
}

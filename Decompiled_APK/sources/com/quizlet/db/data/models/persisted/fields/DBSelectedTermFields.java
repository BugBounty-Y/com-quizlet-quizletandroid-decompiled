package com.quizlet.db.data.models.persisted.fields;

import com.quizlet.db.data.models.base.ColumnField;
import com.quizlet.db.data.models.base.ModelField;
import com.quizlet.db.data.models.persisted.DBSelectedTerm;
import com.quizlet.db.data.models.persisted.DBStudySet;
import com.quizlet.db.data.models.persisted.DBTerm;
import com.quizlet.db.data.models.persisted.DBUser;
import com.quizlet.db.data.models.persisted.base.ModelType;
import com.quizlet.db.data.models.persisted.base.Models;
import com.quizlet.db.data.orm.NoModelRelationship;
import com.quizlet.db.data.orm.Relationship;

/* loaded from: classes2.dex */
public class DBSelectedTermFields {
    public static final ModelField<DBSelectedTerm, Long> LOCAL_ID;
    public static final Relationship<DBSelectedTerm, DBUser> PERSON;
    public static final Relationship<DBSelectedTerm, DBStudySet> SET;
    public static final Relationship<DBSelectedTerm, DBTerm> TERM;

    public static final class Names {
        public static final String ID = "id";
        public static final String LOCAL_ID = "localGeneratedId";
        public static final String PERSON_ID = "personId";
        public static final String SET_ID = "setId";
        public static final String TERM_ID = "termId";
    }

    static {
        ModelType<DBSelectedTerm> modelType = Models.SELECTED_TERM;
        LOCAL_ID = new ColumnField<DBSelectedTerm, Long>(modelType, "localGeneratedId") { // from class: com.quizlet.db.data.models.persisted.fields.DBSelectedTermFields.1
            @Override // com.quizlet.db.data.models.base.ModelField
            public Long getValue(DBSelectedTerm dBSelectedTerm) {
                return Long.valueOf(dBSelectedTerm.getLocalId());
            }

            @Override // com.quizlet.db.data.models.base.ModelField
            public void setValue(DBSelectedTerm dBSelectedTerm, Long l) {
                dBSelectedTerm.setLocalId(l.longValue());
            }
        };
        SET = new NoModelRelationship<DBSelectedTerm, DBStudySet>(modelType, "setId", Models.STUDY_SET) { // from class: com.quizlet.db.data.models.persisted.fields.DBSelectedTermFields.2
            @Override // com.quizlet.db.data.orm.Relationship
            public String getApiAssociationName() {
                return "set";
            }

            @Override // com.quizlet.db.data.models.base.ModelField
            public Long getValue(DBSelectedTerm dBSelectedTerm) {
                return Long.valueOf(dBSelectedTerm.getSetId());
            }

            @Override // com.quizlet.db.data.models.base.ModelField
            public void setValue(DBSelectedTerm dBSelectedTerm, Long l) {
                dBSelectedTerm.setSetId(l.longValue());
            }
        };
        TERM = new NoModelRelationship<DBSelectedTerm, DBTerm>(modelType, "termId", Models.TERM) { // from class: com.quizlet.db.data.models.persisted.fields.DBSelectedTermFields.3
            @Override // com.quizlet.db.data.orm.Relationship
            public String getApiAssociationName() {
                return "term";
            }

            @Override // com.quizlet.db.data.models.base.ModelField
            public Long getValue(DBSelectedTerm dBSelectedTerm) {
                return Long.valueOf(dBSelectedTerm.getTermId());
            }

            @Override // com.quizlet.db.data.models.base.ModelField
            public void setValue(DBSelectedTerm dBSelectedTerm, Long l) {
                dBSelectedTerm.setTermId(l);
            }
        };
        PERSON = new NoModelRelationship<DBSelectedTerm, DBUser>(modelType, "personId", Models.USER) { // from class: com.quizlet.db.data.models.persisted.fields.DBSelectedTermFields.4
            @Override // com.quizlet.db.data.orm.Relationship
            public String getApiAssociationName() {
                return "user";
            }

            @Override // com.quizlet.db.data.models.base.ModelField
            public Long getValue(DBSelectedTerm dBSelectedTerm) {
                return Long.valueOf(dBSelectedTerm.getPersonId());
            }

            @Override // com.quizlet.db.data.models.base.ModelField
            public void setValue(DBSelectedTerm dBSelectedTerm, Long l) {
                dBSelectedTerm.setPersonId(l.longValue());
            }
        };
    }
}

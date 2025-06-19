package com.quizlet.db.data.models.persisted.fields;

import com.quizlet.db.data.models.base.ColumnField;
import com.quizlet.db.data.models.base.ModelField;
import com.quizlet.db.data.models.persisted.DBEnteredSetPassword;
import com.quizlet.db.data.models.persisted.DBStudySet;
import com.quizlet.db.data.models.persisted.DBUser;
import com.quizlet.db.data.models.persisted.base.ModelType;
import com.quizlet.db.data.models.persisted.base.Models;
import com.quizlet.db.data.orm.NoModelRelationship;
import com.quizlet.db.data.orm.Relationship;

/* loaded from: classes2.dex */
public class DBEnteredSetPasswordFields {
    public static final ModelField<DBEnteredSetPassword, Long> LOCAL_ID;
    public static final Relationship<DBEnteredSetPassword, DBUser> PERSON;
    public static final Relationship<DBEnteredSetPassword, DBStudySet> SET;

    public static final class Names {
        public static final String ID = "id";
        public static final String LOCAL_ID = "localGeneratedId";
        public static final String PERSON_ID = "personId";
        public static final String SET_ID = "setId";
    }

    static {
        ModelType<DBEnteredSetPassword> modelType = Models.ENTERED_SET_PASSWORD;
        LOCAL_ID = new ColumnField<DBEnteredSetPassword, Long>(modelType, "localGeneratedId") { // from class: com.quizlet.db.data.models.persisted.fields.DBEnteredSetPasswordFields.1
            @Override // com.quizlet.db.data.models.base.ModelField
            public Long getValue(DBEnteredSetPassword dBEnteredSetPassword) {
                return Long.valueOf(dBEnteredSetPassword.getLocalId());
            }

            @Override // com.quizlet.db.data.models.base.ModelField
            public void setValue(DBEnteredSetPassword dBEnteredSetPassword, Long l) {
                dBEnteredSetPassword.setLocalId(l.longValue());
            }
        };
        SET = new NoModelRelationship<DBEnteredSetPassword, DBStudySet>(modelType, "setId", Models.STUDY_SET) { // from class: com.quizlet.db.data.models.persisted.fields.DBEnteredSetPasswordFields.2
            @Override // com.quizlet.db.data.orm.Relationship
            public String getApiAssociationName() {
                return "set";
            }

            @Override // com.quizlet.db.data.models.base.ModelField
            public Long getValue(DBEnteredSetPassword dBEnteredSetPassword) {
                return Long.valueOf(dBEnteredSetPassword.getSetId());
            }

            @Override // com.quizlet.db.data.models.base.ModelField
            public void setValue(DBEnteredSetPassword dBEnteredSetPassword, Long l) {
                dBEnteredSetPassword.setSetId(l.longValue());
            }
        };
        PERSON = new NoModelRelationship<DBEnteredSetPassword, DBUser>(modelType, "personId", Models.USER) { // from class: com.quizlet.db.data.models.persisted.fields.DBEnteredSetPasswordFields.3
            @Override // com.quizlet.db.data.orm.Relationship
            public String getApiAssociationName() {
                return "user";
            }

            @Override // com.quizlet.db.data.models.base.ModelField
            public Long getValue(DBEnteredSetPassword dBEnteredSetPassword) {
                return Long.valueOf(dBEnteredSetPassword.getPersonId());
            }

            @Override // com.quizlet.db.data.models.base.ModelField
            public void setValue(DBEnteredSetPassword dBEnteredSetPassword, Long l) {
                dBEnteredSetPassword.setPersonId(l.longValue());
            }
        };
    }
}

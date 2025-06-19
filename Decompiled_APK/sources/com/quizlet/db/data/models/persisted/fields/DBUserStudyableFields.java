package com.quizlet.db.data.models.persisted.fields;

import com.quizlet.db.data.models.base.ColumnField;
import com.quizlet.db.data.models.base.ModelField;
import com.quizlet.db.data.models.persisted.DBStudySet;
import com.quizlet.db.data.models.persisted.DBUser;
import com.quizlet.db.data.models.persisted.DBUserStudyable;
import com.quizlet.db.data.models.persisted.base.ModelType;
import com.quizlet.db.data.models.persisted.base.Models;
import com.quizlet.db.data.orm.NoModelRelationship;
import com.quizlet.db.data.orm.Relationship;
import com.quizlet.generated.enums.G1;

/* loaded from: classes2.dex */
public class DBUserStudyableFields {
    public static final ModelField<DBUserStudyable, Long> LOCAL_ID;
    public static final Relationship<DBUserStudyable, DBUser> PERSON;
    public static final Relationship<DBUserStudyable, DBStudySet> SET;
    public static final ModelField<DBUserStudyable, Long> STUDYABLE_TYPE;

    public static final class Names {
        public static final String DUE_TIMESTAMP = "dueTimestamp";
        public static final String ID = "id";
        public static final String IS_ACTIVE = "isActive";
        public static final String IS_DISMISSED = "isDismissed";
        public static final String LAST_STUDIED_TIMESTAMP = "lastStudiedTimestamp";
        public static final String LOCAL_ID = "localGeneratedId";
        public static final String NOTIFICATION_STATUS = "notificationStatus";
        public static final String PERSON_ID = "personId";
        public static final String START_TIMESTAMP = "startTimestamp";
        public static final String STUDYABLE_ID = "studyableId";
        public static final String STUDYABLE_TYPE = "studyableType";
        public static final String TIMESTAMP = "timestamp";
    }

    static {
        ModelType<DBUserStudyable> modelType = Models.USER_STUDYABLE;
        LOCAL_ID = new ColumnField<DBUserStudyable, Long>(modelType, "localGeneratedId") { // from class: com.quizlet.db.data.models.persisted.fields.DBUserStudyableFields.1
            @Override // com.quizlet.db.data.models.base.ModelField
            public Long getValue(DBUserStudyable dBUserStudyable) {
                return Long.valueOf(dBUserStudyable.getLocalId());
            }

            @Override // com.quizlet.db.data.models.base.ModelField
            public void setValue(DBUserStudyable dBUserStudyable, Long l) {
                dBUserStudyable.setLocalId(l.longValue());
            }
        };
        STUDYABLE_TYPE = new ColumnField<DBUserStudyable, Long>(modelType, Names.STUDYABLE_TYPE) { // from class: com.quizlet.db.data.models.persisted.fields.DBUserStudyableFields.2
            @Override // com.quizlet.db.data.models.base.ModelField
            public Long getValue(DBUserStudyable dBUserStudyable) {
                return Long.valueOf(dBUserStudyable.getStudyableType().intValue());
            }

            @Override // com.quizlet.db.data.models.base.ModelField
            public void setValue(DBUserStudyable dBUserStudyable, Long l) {
                dBUserStudyable.setStudyableType(Integer.valueOf(l.intValue()));
            }
        };
        SET = new NoModelRelationship<DBUserStudyable, DBStudySet>(modelType, Names.STUDYABLE_ID, Models.STUDY_SET) { // from class: com.quizlet.db.data.models.persisted.fields.DBUserStudyableFields.3
            @Override // com.quizlet.db.data.orm.Relationship
            public String getApiAssociationName() {
                return "set";
            }

            @Override // com.quizlet.db.data.models.base.ModelField
            public Long getValue(DBUserStudyable dBUserStudyable) {
                return dBUserStudyable.getStudyableId();
            }

            @Override // com.quizlet.db.data.models.base.ModelField
            public void setValue(DBUserStudyable dBUserStudyable, Long l) {
                dBUserStudyable.setStudyableId(l);
                dBUserStudyable.setStudyableType(Integer.valueOf(G1.SET.b()));
            }
        };
        PERSON = new NoModelRelationship<DBUserStudyable, DBUser>(modelType, "personId", Models.USER) { // from class: com.quizlet.db.data.models.persisted.fields.DBUserStudyableFields.4
            @Override // com.quizlet.db.data.orm.Relationship
            public String getApiAssociationName() {
                return "user";
            }

            @Override // com.quizlet.db.data.models.base.ModelField
            public Long getValue(DBUserStudyable dBUserStudyable) {
                return dBUserStudyable.getPersonId();
            }

            @Override // com.quizlet.db.data.models.base.ModelField
            public void setValue(DBUserStudyable dBUserStudyable, Long l) {
                dBUserStudyable.setPersonId(l);
            }
        };
    }
}

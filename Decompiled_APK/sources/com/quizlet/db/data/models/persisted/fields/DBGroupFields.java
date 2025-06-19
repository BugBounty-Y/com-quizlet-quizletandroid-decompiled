package com.quizlet.db.data.models.persisted.fields;

import com.quizlet.db.data.models.base.AssociationNames;
import com.quizlet.db.data.models.base.ColumnField;
import com.quizlet.db.data.models.base.ModelField;
import com.quizlet.db.data.models.persisted.DBGroup;
import com.quizlet.db.data.models.persisted.DBSchool;
import com.quizlet.db.data.models.persisted.DBUser;
import com.quizlet.db.data.models.persisted.base.ModelType;
import com.quizlet.db.data.models.persisted.base.Models;
import com.quizlet.db.data.orm.Relationship;
import com.quizlet.db.data.orm.SingleRelationship;

/* loaded from: classes2.dex */
public class DBGroupFields {
    public static final Relationship<DBGroup, DBUser> CREATOR;
    public static final ModelField<DBGroup, Long> ID;
    public static final ModelField<DBGroup, Long> LOCAL_ID;
    public static final Relationship<DBGroup, DBSchool> SCHOOL;

    public static final class Names {
        public static final String AUTO_JOIN_LINK = "autoJoinLink";
        public static final String CREATOR_ID = "creatorId";
        public static final String ID = "id";
        public static final String LOCAL_ID = "localGeneratedId";
        public static final String NUM_MEMBERS = "dNumMembers";
        public static final String NUM_SETS = "dNumSets";
        public static final String SCHOOL_ID = "schoolId";
    }

    static {
        ModelType<DBGroup> modelType = Models.GROUP;
        LOCAL_ID = new ColumnField<DBGroup, Long>(modelType, "localGeneratedId") { // from class: com.quizlet.db.data.models.persisted.fields.DBGroupFields.1
            @Override // com.quizlet.db.data.models.base.ModelField
            public Long getValue(DBGroup dBGroup) {
                return Long.valueOf(dBGroup.getLocalId());
            }

            @Override // com.quizlet.db.data.models.base.ModelField
            public void setValue(DBGroup dBGroup, Long l) {
                dBGroup.setLocalId(l.longValue());
            }
        };
        ID = new ColumnField<DBGroup, Long>(modelType, "id") { // from class: com.quizlet.db.data.models.persisted.fields.DBGroupFields.2
            @Override // com.quizlet.db.data.models.base.ModelField
            public Long getValue(DBGroup dBGroup) {
                return Long.valueOf(dBGroup.getId());
            }

            @Override // com.quizlet.db.data.models.base.ModelField
            public void setValue(DBGroup dBGroup, Long l) {
                dBGroup.setId(l.longValue());
            }
        };
        SCHOOL = new SingleRelationship<DBGroup, DBSchool>(modelType, Names.SCHOOL_ID, Models.SCHOOL) { // from class: com.quizlet.db.data.models.persisted.fields.DBGroupFields.3
            @Override // com.quizlet.db.data.orm.Relationship
            public String getApiAssociationName() {
                return "school";
            }

            @Override // com.quizlet.db.data.orm.Relationship
            public boolean isRequired() {
                return false;
            }

            @Override // com.quizlet.db.data.orm.Relationship
            public DBSchool getModel(DBGroup dBGroup) {
                return dBGroup.getSchool();
            }

            @Override // com.quizlet.db.data.models.base.ModelField
            public Long getValue(DBGroup dBGroup) {
                return Long.valueOf(dBGroup.getSchoolId());
            }

            @Override // com.quizlet.db.data.orm.Relationship
            public void setModel(DBGroup dBGroup, DBSchool dBSchool) {
                dBGroup.setSchool(dBSchool);
            }

            @Override // com.quizlet.db.data.models.base.ModelField
            public void setValue(DBGroup dBGroup, Long l) {
                dBGroup.setSchoolId(l.longValue());
            }
        };
        CREATOR = new SingleRelationship<DBGroup, DBUser>(modelType, "creatorId", Models.USER) { // from class: com.quizlet.db.data.models.persisted.fields.DBGroupFields.4
            @Override // com.quizlet.db.data.orm.Relationship
            public String getApiAssociationName() {
                return AssociationNames.CREATOR;
            }

            @Override // com.quizlet.db.data.orm.Relationship
            public DBUser getModel(DBGroup dBGroup) {
                return dBGroup.getCreator();
            }

            @Override // com.quizlet.db.data.models.base.ModelField
            public Long getValue(DBGroup dBGroup) {
                return Long.valueOf(dBGroup.getCreatorId());
            }

            @Override // com.quizlet.db.data.orm.Relationship
            public void setModel(DBGroup dBGroup, DBUser dBUser) {
                dBGroup.setCreator(dBUser);
            }

            @Override // com.quizlet.db.data.models.base.ModelField
            public void setValue(DBGroup dBGroup, Long l) {
                dBGroup.setCreatorId(l.longValue());
            }
        };
    }
}

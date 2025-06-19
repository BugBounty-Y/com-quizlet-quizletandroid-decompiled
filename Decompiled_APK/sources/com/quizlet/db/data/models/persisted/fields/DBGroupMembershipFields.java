package com.quizlet.db.data.models.persisted.fields;

import com.quizlet.db.data.models.base.AssociationNames;
import com.quizlet.db.data.models.base.ColumnField;
import com.quizlet.db.data.models.base.ModelField;
import com.quizlet.db.data.models.persisted.DBGroup;
import com.quizlet.db.data.models.persisted.DBGroupMembership;
import com.quizlet.db.data.models.persisted.DBUser;
import com.quizlet.db.data.models.persisted.base.ModelType;
import com.quizlet.db.data.models.persisted.base.Models;
import com.quizlet.db.data.orm.Relationship;
import com.quizlet.db.data.orm.SingleRelationship;

/* loaded from: classes2.dex */
public class DBGroupMembershipFields {
    public static final Relationship<DBGroupMembership, DBGroup> CLASS;
    public static final ModelField<DBGroupMembership, Long> LOCAL_ID;
    public static final Relationship<DBGroupMembership, DBUser> USER;

    public static final class Names {
        public static final String CLASS_ID = "classId";
        public static final String ID = "id";
        public static final String LOCAL_ID = "localGeneratedId";
        public static final String USER_ID = "userId";
    }

    static {
        ModelType<DBGroupMembership> modelType = Models.GROUP_MEMBERSHIP;
        LOCAL_ID = new ColumnField<DBGroupMembership, Long>(modelType, "localGeneratedId") { // from class: com.quizlet.db.data.models.persisted.fields.DBGroupMembershipFields.1
            @Override // com.quizlet.db.data.models.base.ModelField
            public Long getValue(DBGroupMembership dBGroupMembership) {
                return Long.valueOf(dBGroupMembership.getLocalId());
            }

            @Override // com.quizlet.db.data.models.base.ModelField
            public void setValue(DBGroupMembership dBGroupMembership, Long l) {
                dBGroupMembership.setLocalId(l.longValue());
            }
        };
        CLASS = new SingleRelationship<DBGroupMembership, DBGroup>(modelType, Names.CLASS_ID, Models.GROUP) { // from class: com.quizlet.db.data.models.persisted.fields.DBGroupMembershipFields.2
            @Override // com.quizlet.db.data.orm.Relationship
            public String getApiAssociationName() {
                return AssociationNames.CLASS;
            }

            @Override // com.quizlet.db.data.orm.Relationship
            public DBGroup getModel(DBGroupMembership dBGroupMembership) {
                return dBGroupMembership.getGroup();
            }

            @Override // com.quizlet.db.data.models.base.ModelField
            public Long getValue(DBGroupMembership dBGroupMembership) {
                return Long.valueOf(dBGroupMembership.getClassId());
            }

            @Override // com.quizlet.db.data.orm.Relationship
            public void setModel(DBGroupMembership dBGroupMembership, DBGroup dBGroup) {
                dBGroupMembership.setGroup(dBGroup);
            }

            @Override // com.quizlet.db.data.models.base.ModelField
            public void setValue(DBGroupMembership dBGroupMembership, Long l) {
                dBGroupMembership.setClassId(l.longValue());
            }
        };
        USER = new SingleRelationship<DBGroupMembership, DBUser>(modelType, "userId", Models.USER) { // from class: com.quizlet.db.data.models.persisted.fields.DBGroupMembershipFields.3
            @Override // com.quizlet.db.data.orm.Relationship
            public String getApiAssociationName() {
                return "user";
            }

            @Override // com.quizlet.db.data.orm.Relationship
            public DBUser getModel(DBGroupMembership dBGroupMembership) {
                return dBGroupMembership.getUser();
            }

            @Override // com.quizlet.db.data.models.base.ModelField
            public Long getValue(DBGroupMembership dBGroupMembership) {
                return Long.valueOf(dBGroupMembership.getUserId());
            }

            @Override // com.quizlet.db.data.orm.Relationship
            public void setModel(DBGroupMembership dBGroupMembership, DBUser dBUser) {
                dBGroupMembership.setUser(dBUser);
            }

            @Override // com.quizlet.db.data.models.base.ModelField
            public void setValue(DBGroupMembership dBGroupMembership, Long l) {
                dBGroupMembership.setUserId(l.longValue());
            }
        };
    }
}

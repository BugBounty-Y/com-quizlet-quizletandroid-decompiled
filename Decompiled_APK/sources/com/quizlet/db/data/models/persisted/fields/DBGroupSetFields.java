package com.quizlet.db.data.models.persisted.fields;

import com.quizlet.db.data.models.base.AssociationNames;
import com.quizlet.db.data.models.base.ColumnField;
import com.quizlet.db.data.models.base.ModelField;
import com.quizlet.db.data.models.persisted.DBGroup;
import com.quizlet.db.data.models.persisted.DBGroupSet;
import com.quizlet.db.data.models.persisted.DBStudySet;
import com.quizlet.db.data.models.persisted.DBUser;
import com.quizlet.db.data.models.persisted.base.ModelType;
import com.quizlet.db.data.models.persisted.base.Models;
import com.quizlet.db.data.orm.Relationship;
import com.quizlet.db.data.orm.SingleRelationship;

/* loaded from: classes2.dex */
public class DBGroupSetFields {
    public static final Relationship<DBGroupSet, DBUser> CREATOR;
    public static final Relationship<DBGroupSet, DBGroup> GROUP;
    public static final ModelField<DBGroupSet, Long> LOCAL_ID;
    public static final Relationship<DBGroupSet, DBStudySet> SET;

    public static final class Names {
        public static final String FOLDER_ID = "folderId";
        public static final String GROUP_ID = "groupId";
        public static final String ID = "id";
        public static final String LOCAL_ID = "localGeneratedId";
        public static final String SET_ID = "setId";
        public static final String TIMESTAMP = "timestamp_long";
        public static final String USER_ID = "userId";
    }

    static {
        ModelType<DBGroupSet> modelType = Models.GROUP_SET;
        LOCAL_ID = new ColumnField<DBGroupSet, Long>(modelType, "localGeneratedId") { // from class: com.quizlet.db.data.models.persisted.fields.DBGroupSetFields.1
            @Override // com.quizlet.db.data.models.base.ModelField
            public Long getValue(DBGroupSet dBGroupSet) {
                return Long.valueOf(dBGroupSet.getLocalId());
            }

            @Override // com.quizlet.db.data.models.base.ModelField
            public void setValue(DBGroupSet dBGroupSet, Long l) {
                dBGroupSet.setLocalId(l.longValue());
            }
        };
        GROUP = new SingleRelationship<DBGroupSet, DBGroup>(modelType, "groupId", Models.GROUP) { // from class: com.quizlet.db.data.models.persisted.fields.DBGroupSetFields.2
            @Override // com.quizlet.db.data.orm.Relationship
            public String getApiAssociationName() {
                return AssociationNames.CLASS;
            }

            @Override // com.quizlet.db.data.orm.Relationship
            public DBGroup getModel(DBGroupSet dBGroupSet) {
                return dBGroupSet.getGroup();
            }

            @Override // com.quizlet.db.data.models.base.ModelField
            public Long getValue(DBGroupSet dBGroupSet) {
                return Long.valueOf(dBGroupSet.getClassId());
            }

            @Override // com.quizlet.db.data.orm.Relationship
            public void setModel(DBGroupSet dBGroupSet, DBGroup dBGroup) {
                dBGroupSet.setGroup(dBGroup);
            }

            @Override // com.quizlet.db.data.models.base.ModelField
            public void setValue(DBGroupSet dBGroupSet, Long l) {
                dBGroupSet.setClassId(l.longValue());
            }
        };
        SET = new SingleRelationship<DBGroupSet, DBStudySet>(modelType, "setId", Models.STUDY_SET) { // from class: com.quizlet.db.data.models.persisted.fields.DBGroupSetFields.3
            @Override // com.quizlet.db.data.orm.Relationship
            public String getApiAssociationName() {
                return "set";
            }

            @Override // com.quizlet.db.data.orm.Relationship
            public DBStudySet getModel(DBGroupSet dBGroupSet) {
                return dBGroupSet.getSet();
            }

            @Override // com.quizlet.db.data.models.base.ModelField
            public Long getValue(DBGroupSet dBGroupSet) {
                return Long.valueOf(dBGroupSet.getSetId());
            }

            @Override // com.quizlet.db.data.orm.Relationship
            public void setModel(DBGroupSet dBGroupSet, DBStudySet dBStudySet) {
                dBGroupSet.setSet(dBStudySet);
            }

            @Override // com.quizlet.db.data.models.base.ModelField
            public void setValue(DBGroupSet dBGroupSet, Long l) {
                dBGroupSet.setSetId(l.longValue());
            }
        };
        CREATOR = new SingleRelationship<DBGroupSet, DBUser>(modelType, "userId", Models.USER) { // from class: com.quizlet.db.data.models.persisted.fields.DBGroupSetFields.4
            @Override // com.quizlet.db.data.orm.Relationship
            public String getApiAssociationName() {
                return "user";
            }

            @Override // com.quizlet.db.data.orm.Relationship
            public DBUser getModel(DBGroupSet dBGroupSet) {
                return dBGroupSet.getUser();
            }

            @Override // com.quizlet.db.data.models.base.ModelField
            public Long getValue(DBGroupSet dBGroupSet) {
                return Long.valueOf(dBGroupSet.getUserId());
            }

            @Override // com.quizlet.db.data.orm.Relationship
            public void setModel(DBGroupSet dBGroupSet, DBUser dBUser) {
                dBGroupSet.setUser(dBUser);
            }

            @Override // com.quizlet.db.data.models.base.ModelField
            public void setValue(DBGroupSet dBGroupSet, Long l) {
                dBGroupSet.setUserId(l.longValue());
            }
        };
    }
}

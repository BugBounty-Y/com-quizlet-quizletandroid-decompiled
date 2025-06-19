package com.quizlet.db.data.models.persisted.fields;

import com.quizlet.db.data.models.base.ColumnField;
import com.quizlet.db.data.models.base.ModelField;
import com.quizlet.db.data.models.persisted.DBBookmark;
import com.quizlet.db.data.models.persisted.DBFolder;
import com.quizlet.db.data.models.persisted.DBUser;
import com.quizlet.db.data.models.persisted.base.ModelType;
import com.quizlet.db.data.models.persisted.base.Models;
import com.quizlet.db.data.orm.NoModelRelationship;
import com.quizlet.db.data.orm.Relationship;
import com.quizlet.db.data.orm.SingleRelationship;

/* loaded from: classes2.dex */
public class DBBookmarkFields {
    public static final Relationship<DBBookmark, DBFolder> FOLDER;
    public static final ModelField<DBBookmark, Long> LOCAL_ID;
    public static final Relationship<DBBookmark, DBUser> PERSON;

    public static final class Names {
        public static final String FOLDER_ID = "folderId";
        public static final String ID = "id";
        public static final String LOCAL_ID = "localGeneratedId";
        public static final String PERSON_ID = "personId";
    }

    static {
        ModelType<DBBookmark> modelType = Models.BOOKMARK;
        LOCAL_ID = new ColumnField<DBBookmark, Long>(modelType, "localGeneratedId") { // from class: com.quizlet.db.data.models.persisted.fields.DBBookmarkFields.1
            @Override // com.quizlet.db.data.models.base.ModelField
            public Long getValue(DBBookmark dBBookmark) {
                return Long.valueOf(dBBookmark.getLocalId());
            }

            @Override // com.quizlet.db.data.models.base.ModelField
            public void setValue(DBBookmark dBBookmark, Long l) {
                dBBookmark.setLocalId(l.longValue());
            }
        };
        PERSON = new NoModelRelationship<DBBookmark, DBUser>(modelType, "personId", Models.USER) { // from class: com.quizlet.db.data.models.persisted.fields.DBBookmarkFields.2
            @Override // com.quizlet.db.data.orm.Relationship
            public String getApiAssociationName() {
                return "user";
            }

            @Override // com.quizlet.db.data.models.base.ModelField
            public Long getValue(DBBookmark dBBookmark) {
                return Long.valueOf(dBBookmark.getPersonId());
            }

            @Override // com.quizlet.db.data.models.base.ModelField
            public void setValue(DBBookmark dBBookmark, Long l) {
                dBBookmark.setPersonId(l.longValue());
            }
        };
        FOLDER = new SingleRelationship<DBBookmark, DBFolder>(modelType, "folderId", Models.FOLDER) { // from class: com.quizlet.db.data.models.persisted.fields.DBBookmarkFields.3
            @Override // com.quizlet.db.data.orm.Relationship
            public String getApiAssociationName() {
                return "folder";
            }

            @Override // com.quizlet.db.data.orm.Relationship
            public DBFolder getModel(DBBookmark dBBookmark) {
                return dBBookmark.getFolder();
            }

            @Override // com.quizlet.db.data.models.base.ModelField
            public Long getValue(DBBookmark dBBookmark) {
                return Long.valueOf(dBBookmark.getFolderId());
            }

            @Override // com.quizlet.db.data.orm.Relationship
            public void setModel(DBBookmark dBBookmark, DBFolder dBFolder) {
                dBBookmark.setFolder(dBFolder);
            }

            @Override // com.quizlet.db.data.models.base.ModelField
            public void setValue(DBBookmark dBBookmark, Long l) {
                dBBookmark.setFolderId(l.longValue());
            }
        };
    }
}

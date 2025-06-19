package com.quizlet.db.data.models.persisted.fields;

import com.quizlet.db.data.models.base.AssociationNames;
import com.quizlet.db.data.models.base.ColumnField;
import com.quizlet.db.data.models.base.ModelField;
import com.quizlet.db.data.models.persisted.DBFolder;
import com.quizlet.db.data.models.persisted.DBGroup;
import com.quizlet.db.data.models.persisted.DBGroupFolder;
import com.quizlet.db.data.models.persisted.base.ModelType;
import com.quizlet.db.data.models.persisted.base.Models;
import com.quizlet.db.data.orm.NoModelRelationship;
import com.quizlet.db.data.orm.Relationship;
import com.quizlet.db.data.orm.SingleRelationship;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class DBGroupFolderFields {

    @NotNull
    private static final Relationship<DBGroupFolder, DBFolder> FOLDER;

    @NotNull
    private static final Relationship<DBGroupFolder, DBGroup> GROUP;

    @NotNull
    public static final DBGroupFolderFields INSTANCE = new DBGroupFolderFields();

    @NotNull
    private static final ModelField<DBGroupFolder, Long> LOCAL_ID;

    @Metadata
    public static final class Names {

        @NotNull
        public static final String CAN_EDIT = "canEdit";

        @NotNull
        public static final String FOLDER_ID = "folderId";

        @NotNull
        public static final String GROUP_ID = "groupId";

        @NotNull
        public static final Names INSTANCE = new Names();

        @NotNull
        public static final String LOCAL_ID = "localGeneratedId";

        @NotNull
        public static final String TIMESTAMP = "timestamp";

        private Names() {
        }
    }

    static {
        final ModelType<DBGroupFolder> modelType = Models.GROUP_FOLDER;
        LOCAL_ID = new ColumnField<DBGroupFolder, Long>(modelType) { // from class: com.quizlet.db.data.models.persisted.fields.DBGroupFolderFields$LOCAL_ID$1
            @Override // com.quizlet.db.data.models.base.ModelField
            public Long getValue(DBGroupFolder model) {
                Intrinsics.checkNotNullParameter(model, "model");
                return Long.valueOf(model.getLocalId());
            }

            @Override // com.quizlet.db.data.models.base.ModelField
            public void setValue(DBGroupFolder model, Long l) {
                Intrinsics.checkNotNullParameter(model, "model");
                Intrinsics.d(l);
                model.setLocalId(l.longValue());
            }
        };
        final ModelType<DBFolder> modelType2 = Models.FOLDER;
        FOLDER = new SingleRelationship<DBGroupFolder, DBFolder>(modelType, modelType2) { // from class: com.quizlet.db.data.models.persisted.fields.DBGroupFolderFields$FOLDER$1
            @Override // com.quizlet.db.data.orm.Relationship
            public String getApiAssociationName() {
                return "folder";
            }

            @Override // com.quizlet.db.data.orm.Relationship
            public DBFolder getModel(DBGroupFolder groupFolder) {
                Intrinsics.checkNotNullParameter(groupFolder, "groupFolder");
                DBFolder folder = groupFolder.getFolder();
                Intrinsics.checkNotNullExpressionValue(folder, "getFolder(...)");
                return folder;
            }

            @Override // com.quizlet.db.data.models.base.ModelField
            public Long getValue(DBGroupFolder model) {
                Intrinsics.checkNotNullParameter(model, "model");
                return Long.valueOf(model.getFolderId());
            }

            @Override // com.quizlet.db.data.orm.Relationship
            public void setModel(DBGroupFolder groupFolder, DBFolder dBFolder) {
                Intrinsics.checkNotNullParameter(groupFolder, "groupFolder");
                groupFolder.setFolder(dBFolder);
            }

            @Override // com.quizlet.db.data.models.base.ModelField
            public void setValue(DBGroupFolder model, Long l) {
                Intrinsics.checkNotNullParameter(model, "model");
                Intrinsics.d(l);
                model.setFolderId(l.longValue());
            }
        };
        final ModelType<DBGroup> modelType3 = Models.GROUP;
        GROUP = new NoModelRelationship<DBGroupFolder, DBGroup>(modelType, modelType3) { // from class: com.quizlet.db.data.models.persisted.fields.DBGroupFolderFields$GROUP$1
            @Override // com.quizlet.db.data.orm.Relationship
            public String getApiAssociationName() {
                return AssociationNames.CLASS;
            }

            @Override // com.quizlet.db.data.models.base.ModelField
            public Long getValue(DBGroupFolder model) {
                Intrinsics.checkNotNullParameter(model, "model");
                return Long.valueOf(model.getClassId());
            }

            @Override // com.quizlet.db.data.models.base.ModelField
            public void setValue(DBGroupFolder model, Long l) {
                Intrinsics.checkNotNullParameter(model, "model");
                Intrinsics.d(l);
                model.setClassId(l.longValue());
            }
        };
    }

    private DBGroupFolderFields() {
    }

    @NotNull
    public final Relationship<DBGroupFolder, DBFolder> getFOLDER() {
        return FOLDER;
    }

    @NotNull
    public final Relationship<DBGroupFolder, DBGroup> getGROUP() {
        return GROUP;
    }

    @NotNull
    public final ModelField<DBGroupFolder, Long> getLOCAL_ID() {
        return LOCAL_ID;
    }
}

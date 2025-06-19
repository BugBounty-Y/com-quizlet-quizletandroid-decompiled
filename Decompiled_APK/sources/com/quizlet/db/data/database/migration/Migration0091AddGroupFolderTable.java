package com.quizlet.db.data.database.migration;

import com.quizlet.android.migrator.migrations.c;
import com.quizlet.android.migrator.migrations.changes.a;
import com.quizlet.db.data.models.persisted.DBGroupFolder;
import kotlin.Metadata;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class Migration0091AddGroupFolderTable extends c {

    @NotNull
    private static final String CREATE_TABLE_STATEMENT = "\nCREATE TABLE `group_folder` (\n    `localGeneratedId` BIGINT,\n    `groupId` BIGINT,\n    `folderId` BIGINT,\n    `canEdit` SMALLINT,\n    `timestamp` BIGINT,\n    `dirty` SMALLINT,\n    `isDeleted` SMALLINT,\n    `lastModified` BIGINT,\n    `clientTimestamp` BIGINT,\n    UNIQUE(`groupId`,`folderId`),\n    PRIMARY KEY (`localGeneratedId`)\n)\n            ";

    @Metadata
    public static final class Companion {
    }

    @Override // com.quizlet.android.migrator.migrations.b
    public com.quizlet.android.migrator.migrations.changes.c getChange() {
        return new a(DBGroupFolder.class, DBGroupFolder.TABLE_NAME, CREATE_TABLE_STATEMENT);
    }
}

package com.quizlet.db.data.database.migration;

import com.quizlet.android.migrator.migrations.c;
import com.quizlet.android.migrator.migrations.changes.a;
import com.quizlet.db.data.models.persisted.DBUserStudyable;

/* loaded from: classes2.dex */
public class Migration0063AddUserStudyableTable extends c {
    private static final String CREATE_TABLE_STATEMENT = "CREATE TABLE `userStudyable` (`id` BIGINT , `localGeneratedId` BIGINT , `personId` BIGINT , `studyableType` INTEGER , `studyableId` BIGINT , `startTimestamp` BIGINT , `dueTimestamp` BIGINT , `notificationStatus` INTEGER , `lastStudiedTimestamp` BIGINT, `isDismissed` SMALLINT, `timestamp` BIGINT , `isActive` INTEGER , `dirty` SMALLINT , `isDeleted` SMALLINT , `lastModified` BIGINT , PRIMARY KEY (`id`) ) ";

    @Override // com.quizlet.android.migrator.migrations.b
    public final com.quizlet.android.migrator.migrations.changes.c getChange() {
        return new a(DBUserStudyable.class, DBUserStudyable.TABLE_NAME, CREATE_TABLE_STATEMENT);
    }
}

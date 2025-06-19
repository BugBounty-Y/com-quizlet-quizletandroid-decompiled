package com.quizlet.db.data.database.migration;

import com.quizlet.android.migrator.migrations.c;
import com.quizlet.android.migrator.migrations.changes.a;
import com.quizlet.db.data.models.persisted.DBProgressReset;
import kotlin.Metadata;

@Metadata
/* loaded from: classes2.dex */
public final class Migration0094CreateProgressResetTable extends c {
    @Override // com.quizlet.android.migrator.migrations.b
    public com.quizlet.android.migrator.migrations.changes.c getChange() {
        return new a(DBProgressReset.class, DBProgressReset.TABLE_NAME, "CREATE TABLE `progress_reset` (\n`localGeneratedId` BIGINT,\n`dirty` SMALLINT,\n`isDeleted` SMALLINT,\n`lastModified` BIGINT,\n`clientTimestamp` BIGINT,\n`personId` BIGINT,\n`containerId` BIGINT,\n`containerType` SMALLINT,\n`resetTimeSec` BIGINT,\nUNIQUE(`personId`,`containerId`,`containerType`),\nPRIMARY KEY (`localGeneratedId`));");
    }
}

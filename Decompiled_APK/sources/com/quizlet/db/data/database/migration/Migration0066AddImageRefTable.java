package com.quizlet.db.data.database.migration;

import com.quizlet.android.migrator.migrations.c;
import com.quizlet.android.migrator.migrations.changes.a;
import com.quizlet.db.data.models.persisted.DBImageRef;

/* loaded from: classes2.dex */
public class Migration0066AddImageRefTable extends c {
    private static final String CREATE_TABLE_STATEMENT = "CREATE TABLE `imageRef` (`id` BIGINT,`localGeneratedId` BIGINT,`modelId` BIGINT,`modelType` INTEGER,`imageId` BIGINT,`imageType` INTEGER,`timestamp` BIGINT,`dirty` SMALLINT,`isDeleted` SMALLINT,`lastModified` BIGINT,PRIMARY KEY (`id`))";

    @Override // com.quizlet.android.migrator.migrations.b
    public final com.quizlet.android.migrator.migrations.changes.c getChange() {
        return new a(DBImageRef.class, DBImageRef.TABLE_NAME, CREATE_TABLE_STATEMENT);
    }
}

package com.quizlet.db.data.database.migration;

import com.quizlet.android.migrator.migrations.c;
import com.quizlet.android.migrator.migrations.changes.a;
import com.quizlet.db.data.models.persisted.DBDiagramShape;

/* loaded from: classes2.dex */
public class Migration0067AddDiagramShapeTable extends c {
    private static final String CREATE_TABLE_STATEMENT = "CREATE TABLE `diagramShape` (`id` BIGINT,`localGeneratedId` BIGINT,`termId` BIGINT,`setId` BIGINT,`shape` VARCHAR,`timestamp` BIGINT,`dirty` SMALLINT,`isDeleted` SMALLINT,`lastModified` BIGINT,PRIMARY KEY (`id`))";

    @Override // com.quizlet.android.migrator.migrations.b
    public final com.quizlet.android.migrator.migrations.changes.c getChange() {
        return new a(DBDiagramShape.class, DBDiagramShape.TABLE_NAME, CREATE_TABLE_STATEMENT);
    }
}

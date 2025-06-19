package com.quizlet.db.data.database.migration;

import com.quizlet.android.migrator.migrations.c;
import com.quizlet.android.migrator.migrations.changes.a;
import com.quizlet.db.data.models.persisted.DBOfflineEntity;
import kotlin.Metadata;

@Metadata
/* loaded from: classes2.dex */
public final class Migration0086RecreateOfflineEntityTable extends c {
    @Override // com.quizlet.android.migrator.migrations.b
    public com.quizlet.android.migrator.migrations.changes.c getChange() {
        return new a(DBOfflineEntity.class, DBOfflineEntity.TABLE_NAME, "CREATE TABLE `offline_entity` (\n`model_id` BIGINT,\n`model_type` INTEGER,\n`offline_status` INTEGER,\n`localGeneratedId` BIGINT,\n`dirty` SMALLINT,\n`isDeleted` SMALLINT,\n`lastModified` BIGINT,\n`clientTimestamp` BIGINT,\nPRIMARY KEY (`localGeneratedId`));");
    }
}

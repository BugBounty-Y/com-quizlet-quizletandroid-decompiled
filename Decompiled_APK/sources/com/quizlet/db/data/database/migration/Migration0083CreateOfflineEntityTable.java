package com.quizlet.db.data.database.migration;

import com.quizlet.android.migrator.migrations.c;
import com.quizlet.android.migrator.migrations.changes.a;
import com.quizlet.db.data.models.persisted.DBOfflineEntity;
import kotlin.Metadata;

@Metadata
/* loaded from: classes2.dex */
public final class Migration0083CreateOfflineEntityTable extends c {

    @Metadata
    public static final class Companion {
    }

    @Override // com.quizlet.android.migrator.migrations.b
    public com.quizlet.android.migrator.migrations.changes.c getChange() {
        return new a(DBOfflineEntity.class, DBOfflineEntity.TABLE_NAME, "CREATE TABLE `offline_entity` (`id` BIGINT,`model_id` BIGINT,`model_type` INTEGER,`offline_status` INTEGER,`localGeneratedId` BIGINT,`dirty` SMALLINT,`isDeleted` SMALLINT,`lastModified` BIGINT,`clientTimestamp` BIGINT,PRIMARY KEY (`id`));");
    }
}

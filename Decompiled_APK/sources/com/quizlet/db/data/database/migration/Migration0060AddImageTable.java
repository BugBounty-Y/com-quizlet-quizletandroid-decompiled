package com.quizlet.db.data.database.migration;

import com.quizlet.android.migrator.migrations.c;
import com.quizlet.android.migrator.migrations.changes.a;
import com.quizlet.db.data.models.persisted.DBImage;

/* loaded from: classes2.dex */
public class Migration0060AddImageTable extends c {
    @Override // com.quizlet.android.migrator.migrations.b
    public final com.quizlet.android.migrator.migrations.changes.c getChange() {
        return new a(DBImage.class, "image", "CREATE TABLE `image` (`code` VARCHAR , `height` INTEGER , `id` BIGINT , `localGeneratedId` BIGINT , `localPath` VARCHAR , `dMediumUrl` VARCHAR , `dLargeUrl` VARCHAR , `personId` BIGINT , `dSmallUrl` VARCHAR , `timestamp` BIGINT , `width` INTEGER , `dirty` SMALLINT , `isDeleted` SMALLINT , `lastModified` BIGINT , PRIMARY KEY (`id`) ) ");
    }
}

package com.quizlet.db.data.database.migration;

import com.quizlet.android.migrator.migrations.c;
import com.quizlet.android.migrator.migrations.changes.a;
import com.quizlet.db.data.models.persisted.DBStudySetting;

/* loaded from: classes2.dex */
public class Migration0049AddStudySettingTable extends c {
    @Override // com.quizlet.android.migrator.migrations.b
    public final com.quizlet.android.migrator.migrations.changes.c getChange() {
        return new a(DBStudySetting.class, DBStudySetting.TABLE_NAME, "CREATE TABLE `study_setting` (`studyable_type` INTEGER , `timestamp` BIGINT , `setting_value` BIGINT , `studyable_id` BIGINT , `localGeneratedId` BIGINT , `personId` BIGINT , `setting_type` INTEGER , `dirty` SMALLINT , `lastModified` BIGINT , `isDeleted` SMALLINT , PRIMARY KEY (`localGeneratedId`) , UNIQUE (`studyable_type`,`studyable_id`,`personId`,`setting_type`) );");
    }
}

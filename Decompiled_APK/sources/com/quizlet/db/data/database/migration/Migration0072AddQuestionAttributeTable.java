package com.quizlet.db.data.database.migration;

import com.quizlet.android.migrator.migrations.c;
import com.quizlet.android.migrator.migrations.changes.a;
import com.quizlet.db.data.models.persisted.DBQuestionAttribute;

/* loaded from: classes2.dex */
public class Migration0072AddQuestionAttributeTable extends c {
    private final String CREATE_TABLE_STATEMENT;

    public Migration0072AddQuestionAttributeTable() {
        super(72, 0);
        this.CREATE_TABLE_STATEMENT = "CREATE TABLE `question_attribute` (`id` BIGINT,`localGeneratedId` BIGINT,`answerId` BIGINT,`personId` BIGINT,`questionSide` SMALLINT,`setId` BIGINT,`termId` BIGINT,`termSide` SMALLINT,`timestamp` BIGINT,`dirty` SMALLINT,`isDeleted` SMALLINT,`lastModified` BIGINT,PRIMARY KEY (`id`))";
    }

    @Override // com.quizlet.android.migrator.migrations.b
    public final com.quizlet.android.migrator.migrations.changes.c getChange() {
        return new a(DBQuestionAttribute.class, DBQuestionAttribute.TABLE_NAME, this.CREATE_TABLE_STATEMENT);
    }
}

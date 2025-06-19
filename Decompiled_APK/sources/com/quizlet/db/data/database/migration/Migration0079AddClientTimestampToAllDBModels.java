package com.quizlet.db.data.database.migration;

import androidx.compose.runtime.AbstractC0772a;
import com.quizlet.android.migrator.a;
import com.quizlet.android.migrator.migrations.e;
import com.quizlet.android.migrator.tools.c;
import com.quizlet.db.billing.model.DBSubscription;
import com.quizlet.db.data.models.base.BaseDBModel;
import com.quizlet.db.data.models.persisted.DBAnswer;
import com.quizlet.db.data.models.persisted.DBBookmark;
import com.quizlet.db.data.models.persisted.DBDiagramShape;
import com.quizlet.db.data.models.persisted.DBEnteredSetPassword;
import com.quizlet.db.data.models.persisted.DBFolder;
import com.quizlet.db.data.models.persisted.DBGroup;
import com.quizlet.db.data.models.persisted.DBGroupMembership;
import com.quizlet.db.data.models.persisted.DBGroupSet;
import com.quizlet.db.data.models.persisted.DBImage;
import com.quizlet.db.data.models.persisted.DBImageRef;
import com.quizlet.db.data.models.persisted.DBQuestionAttribute;
import com.quizlet.db.data.models.persisted.DBSchool;
import com.quizlet.db.data.models.persisted.DBSelectedTerm;
import com.quizlet.db.data.models.persisted.DBSession;
import com.quizlet.db.data.models.persisted.DBStudySet;
import com.quizlet.db.data.models.persisted.DBStudySetting;
import com.quizlet.db.data.models.persisted.DBTerm;
import com.quizlet.db.data.models.persisted.DBUser;
import com.quizlet.db.data.models.persisted.DBUserStudyable;
import com.quizlet.db.data.models.persisted.fields.BaseDBModelFields;
import java.sql.SQLException;
import java.util.Map;
import kotlin.Metadata;
import kotlin.Pair;
import kotlin.collections.V;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class Migration0079AddClientTimestampToAllDBModels extends e {
    public static final Companion b = new Companion();

    @NotNull
    private static final Map<Class<? extends BaseDBModel>, String> tables = V.f(new Pair(DBAnswer.class, "answer"), new Pair(DBBookmark.class, DBBookmark.TABLE_NAME), new Pair(DBDiagramShape.class, DBDiagramShape.TABLE_NAME), new Pair(DBEnteredSetPassword.class, DBEnteredSetPassword.TABLE_NAME), new Pair(DBFolder.class, "folder"), new Pair(DBGroup.class, DBGroup.TABLE_NAME), new Pair(DBGroupMembership.class, DBGroupMembership.TABLE_NAME), new Pair(DBGroupSet.class, DBGroupSet.TABLE_NAME), new Pair(DBImage.class, "image"), new Pair(DBImageRef.class, DBImageRef.TABLE_NAME), new Pair(DBQuestionAttribute.class, DBQuestionAttribute.TABLE_NAME), new Pair(DBSchool.class, "school"), new Pair(DBSelectedTerm.class, DBSelectedTerm.TABLE_NAME), new Pair(DBSession.class, "session"), new Pair(DBStudySet.class, "set"), new Pair(DBStudySetting.class, DBStudySetting.TABLE_NAME), new Pair(DBSubscription.class, DBSubscription.TABLE_NAME), new Pair(DBTerm.class, "term"), new Pair(DBUser.class, "user"), new Pair(DBUserStudyable.class, DBUserStudyable.TABLE_NAME));

    @Metadata
    public static final class Companion {
        @NotNull
        public final Map<Class<? extends BaseDBModel>, String> getTables() {
            return Migration0079AddClientTimestampToAllDBModels.tables;
        }
    }

    @Override // com.quizlet.android.migrator.migrations.a
    public final void b(AbstractC0772a abstractC0772a) throws SQLException {
        c schemaTools = (c) abstractC0772a;
        Intrinsics.checkNotNullParameter(schemaTools, "schemaTools");
        for (Map.Entry<Class<? extends BaseDBModel>, String> entry : tables.entrySet()) {
            schemaTools.o(entry.getKey(), entry.getValue(), BaseDBModelFields.Names.CLIENT_TIMESTAMP, a.b);
        }
    }
}

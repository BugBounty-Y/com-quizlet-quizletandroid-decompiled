package com.quizlet.db.data.models.persisted.fields;

import com.quizlet.db.data.models.base.ColumnField;
import com.quizlet.db.data.models.base.ModelField;
import com.quizlet.db.data.models.persisted.DBProgressReset;
import com.quizlet.db.data.models.persisted.base.ModelType;
import com.quizlet.db.data.models.persisted.base.Models;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class DBProgressResetFields {

    @NotNull
    private static final ModelField<DBProgressReset, Long> CONTAINER;

    @NotNull
    private static final ModelField<DBProgressReset, Long> CONTAINER_TYPE;

    @NotNull
    public static final DBProgressResetFields INSTANCE = new DBProgressResetFields();

    @NotNull
    private static final ModelField<DBProgressReset, Long> LOCAL_ID;

    @NotNull
    private static final ModelField<DBProgressReset, Long> USER;

    @Metadata
    public static final class Names {

        @NotNull
        public static final String CONTAINER_ID = "containerId";

        @NotNull
        public static final String CONTAINER_TYPE = "containerType";

        @NotNull
        public static final Names INSTANCE = new Names();

        @NotNull
        public static final String LOCAL_ID = "localGeneratedId";

        @NotNull
        public static final String PERSON_ID = "personId";

        @NotNull
        public static final String RESET_TIME_SEC = "resetTimeSec";

        private Names() {
        }
    }

    static {
        final ModelType<DBProgressReset> modelType = Models.PROGRESS_RESET;
        LOCAL_ID = new ColumnField<DBProgressReset, Long>(modelType) { // from class: com.quizlet.db.data.models.persisted.fields.DBProgressResetFields$LOCAL_ID$1
            @Override // com.quizlet.db.data.models.base.ModelField
            public Long getValue(DBProgressReset model) {
                Intrinsics.checkNotNullParameter(model, "model");
                return Long.valueOf(model.getLocalId());
            }

            @Override // com.quizlet.db.data.models.base.ModelField
            public void setValue(DBProgressReset model, Long l) {
                Intrinsics.checkNotNullParameter(model, "model");
                Intrinsics.d(l);
                model.setLocalId(l.longValue());
            }
        };
        USER = new ColumnField<DBProgressReset, Long>(modelType) { // from class: com.quizlet.db.data.models.persisted.fields.DBProgressResetFields$USER$1
            @Override // com.quizlet.db.data.models.base.ModelField
            public Long getValue(DBProgressReset model) {
                Intrinsics.checkNotNullParameter(model, "model");
                return Long.valueOf(model.getPersonId());
            }

            @Override // com.quizlet.db.data.models.base.ModelField
            public void setValue(DBProgressReset model, Long l) {
                Intrinsics.checkNotNullParameter(model, "model");
                Intrinsics.d(l);
                model.setPersonId(l.longValue());
            }
        };
        CONTAINER = new ColumnField<DBProgressReset, Long>(modelType) { // from class: com.quizlet.db.data.models.persisted.fields.DBProgressResetFields$CONTAINER$1
            @Override // com.quizlet.db.data.models.base.ModelField
            public Long getValue(DBProgressReset model) {
                Intrinsics.checkNotNullParameter(model, "model");
                return Long.valueOf(model.getContainerId());
            }

            @Override // com.quizlet.db.data.models.base.ModelField
            public void setValue(DBProgressReset model, Long l) {
                Intrinsics.checkNotNullParameter(model, "model");
                Intrinsics.d(l);
                model.setContainerId(l.longValue());
            }
        };
        CONTAINER_TYPE = new ColumnField<DBProgressReset, Long>(modelType) { // from class: com.quizlet.db.data.models.persisted.fields.DBProgressResetFields$CONTAINER_TYPE$1
            @Override // com.quizlet.db.data.models.base.ModelField
            public Long getValue(DBProgressReset model) {
                Intrinsics.checkNotNullParameter(model, "model");
                return Long.valueOf(model.getContainerType());
            }

            @Override // com.quizlet.db.data.models.base.ModelField
            public void setValue(DBProgressReset model, Long l) {
                Intrinsics.checkNotNullParameter(model, "model");
                Intrinsics.d(l);
                model.setContainerType((short) l.longValue());
            }
        };
    }

    private DBProgressResetFields() {
    }

    @NotNull
    public final ModelField<DBProgressReset, Long> getCONTAINER() {
        return CONTAINER;
    }

    @NotNull
    public final ModelField<DBProgressReset, Long> getCONTAINER_TYPE() {
        return CONTAINER_TYPE;
    }

    @NotNull
    public final ModelField<DBProgressReset, Long> getLOCAL_ID() {
        return LOCAL_ID;
    }

    @NotNull
    public final ModelField<DBProgressReset, Long> getUSER() {
        return USER;
    }
}

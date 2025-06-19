package com.quizlet.db.data.models.persisted.fields;

import com.quizlet.db.data.models.base.ColumnField;
import com.quizlet.db.data.models.base.ModelField;
import com.quizlet.db.data.models.persisted.DBSchool;
import com.quizlet.db.data.models.persisted.base.ModelType;
import com.quizlet.db.data.models.persisted.base.Models;

/* loaded from: classes2.dex */
public class DBSchoolFields {
    public static final ModelField<DBSchool, Long> ID;
    public static final ModelField<DBSchool, Long> LOCAL_ID;

    public static final class Names {
        public static final String ID = "id";
        public static final String LOCAL_ID = "localGeneratedId";
    }

    static {
        ModelType<DBSchool> modelType = Models.SCHOOL;
        LOCAL_ID = new ColumnField<DBSchool, Long>(modelType, "localGeneratedId") { // from class: com.quizlet.db.data.models.persisted.fields.DBSchoolFields.1
            @Override // com.quizlet.db.data.models.base.ModelField
            public Long getValue(DBSchool dBSchool) {
                return Long.valueOf(dBSchool.getLocalId());
            }

            @Override // com.quizlet.db.data.models.base.ModelField
            public void setValue(DBSchool dBSchool, Long l) {
                dBSchool.setLocalId(l.longValue());
            }
        };
        ID = new ColumnField<DBSchool, Long>(modelType, "id") { // from class: com.quizlet.db.data.models.persisted.fields.DBSchoolFields.2
            @Override // com.quizlet.db.data.models.base.ModelField
            public Long getValue(DBSchool dBSchool) {
                return Long.valueOf(dBSchool.getId());
            }

            @Override // com.quizlet.db.data.models.base.ModelField
            public void setValue(DBSchool dBSchool, Long l) {
                dBSchool.setId(l.longValue());
            }
        };
    }
}

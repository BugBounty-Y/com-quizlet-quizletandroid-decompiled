package com.quizlet.db.data.models.persisted.fields;

import com.quizlet.db.data.models.base.ColumnField;
import com.quizlet.db.data.models.base.ModelField;
import com.quizlet.db.data.models.persisted.DBImage;
import com.quizlet.db.data.models.persisted.base.ModelType;
import com.quizlet.db.data.models.persisted.base.Models;

/* loaded from: classes2.dex */
public class DBImageFields {
    public static final ModelField<DBImage, Long> ID;
    public static final ModelField<DBImage, Long> LOCAL_ID;

    public static final class Names {
        public static final String ID = "id";
        public static final String LARGE_URL = "dLargeUrl";
        public static final String LOCAL_ID = "localGeneratedId";
        public static final String LOCAL_PATH = "localPath";
        public static final String MEDIUM_URL = "dMediumUrl";
        public static final String SMALL_URL = "dSmallUrl";
        public static final String SQUARE_URL = "dSquareUrl";
    }

    static {
        ModelType<DBImage> modelType = Models.IMAGE;
        LOCAL_ID = new ColumnField<DBImage, Long>(modelType, "localGeneratedId") { // from class: com.quizlet.db.data.models.persisted.fields.DBImageFields.1
            @Override // com.quizlet.db.data.models.base.ModelField
            public Long getValue(DBImage dBImage) {
                return Long.valueOf(dBImage.getLocalId());
            }

            @Override // com.quizlet.db.data.models.base.ModelField
            public void setValue(DBImage dBImage, Long l) {
                dBImage.setLocalId(l.longValue());
            }
        };
        ID = new ColumnField<DBImage, Long>(modelType, "id") { // from class: com.quizlet.db.data.models.persisted.fields.DBImageFields.2
            @Override // com.quizlet.db.data.models.base.ModelField
            public Long getValue(DBImage dBImage) {
                return Long.valueOf(dBImage.getId());
            }

            @Override // com.quizlet.db.data.models.base.ModelField
            public void setValue(DBImage dBImage, Long l) {
                dBImage.setId(l.longValue());
            }
        };
    }
}

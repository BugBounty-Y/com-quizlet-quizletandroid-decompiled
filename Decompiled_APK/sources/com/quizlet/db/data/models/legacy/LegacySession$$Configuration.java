package com.quizlet.db.data.models.legacy;

import com.j256.ormlite.field.DatabaseFieldConfig;
import com.j256.ormlite.table.DatabaseTableConfig;
import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.db.data.models.persisted.fields.BaseDBModelFields;
import java.util.ArrayList;
import java.util.List;

/* loaded from: classes2.dex */
public final class LegacySession$$Configuration {
    public static List<DatabaseFieldConfig> getFieldConfigs() {
        ArrayList arrayList = new ArrayList();
        DatabaseFieldConfig databaseFieldConfigE = AbstractC4178x.e("id", "id", true, 2, arrayList);
        DatabaseFieldConfig databaseFieldConfigD = AbstractC4178x.d(databaseFieldConfigE, "mode", 2, arrayList, databaseFieldConfigE);
        DatabaseFieldConfig databaseFieldConfigD2 = AbstractC4178x.d(databaseFieldConfigD, "startDate", 2, arrayList, databaseFieldConfigD);
        DatabaseFieldConfig databaseFieldConfigD3 = AbstractC4178x.d(databaseFieldConfigD2, "finishDate", 2, arrayList, databaseFieldConfigD2);
        DatabaseFieldConfig databaseFieldConfigD4 = AbstractC4178x.d(databaseFieldConfigD3, "imageUrl", 2, arrayList, databaseFieldConfigD3);
        DatabaseFieldConfig databaseFieldConfigD5 = AbstractC4178x.d(databaseFieldConfigD4, "formattedScore", 2, arrayList, databaseFieldConfigD4);
        DatabaseFieldConfig databaseFieldConfigD6 = AbstractC4178x.d(databaseFieldConfigD5, "setId", 2, arrayList, databaseFieldConfigD5);
        AbstractC4178x.q(databaseFieldConfigD6, "localId", "localGeneratedId", 2);
        DatabaseFieldConfig databaseFieldConfigF = AbstractC4178x.f(arrayList, databaseFieldConfigD6, "dirty", "dirty", 2);
        AbstractC4178x.q(databaseFieldConfigF, "isDeleted", "isDeleted", 2);
        DatabaseFieldConfig databaseFieldConfigF2 = AbstractC4178x.f(arrayList, databaseFieldConfigF, "lastModified", "lastModified", 2);
        AbstractC4178x.q(databaseFieldConfigF2, BaseDBModelFields.Names.CLIENT_TIMESTAMP, BaseDBModelFields.Names.CLIENT_TIMESTAMP, 2);
        arrayList.add(databaseFieldConfigF2);
        return arrayList;
    }

    public static DatabaseTableConfig<LegacySession> getTableConfig() {
        DatabaseTableConfig<LegacySession> databaseTableConfigG = AbstractC4178x.g(LegacySession.class, "legacy_session");
        databaseTableConfigG.setFieldConfigs(getFieldConfigs());
        return databaseTableConfigG;
    }
}

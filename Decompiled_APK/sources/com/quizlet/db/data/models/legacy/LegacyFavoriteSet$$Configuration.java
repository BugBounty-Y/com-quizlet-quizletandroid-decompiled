package com.quizlet.db.data.models.legacy;

import com.j256.ormlite.field.DatabaseFieldConfig;
import com.j256.ormlite.table.DatabaseTableConfig;
import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.db.data.models.persisted.fields.BaseDBModelFields;
import com.quizlet.db.data.models.persisted.fields.DBGroupFolderFields;
import java.util.ArrayList;
import java.util.List;

/* loaded from: classes2.dex */
public final class LegacyFavoriteSet$$Configuration {
    public static List<DatabaseFieldConfig> getFieldConfigs() {
        ArrayList arrayList = new ArrayList();
        DatabaseFieldConfig databaseFieldConfigE = AbstractC4178x.e("id", "id", true, 2, arrayList);
        DatabaseFieldConfig databaseFieldConfigD = AbstractC4178x.d(databaseFieldConfigE, DBGroupFolderFields.Names.CAN_EDIT, 2, arrayList, databaseFieldConfigE);
        DatabaseFieldConfig databaseFieldConfigD2 = AbstractC4178x.d(databaseFieldConfigD, "timestamp", 2, arrayList, databaseFieldConfigD);
        DatabaseFieldConfig databaseFieldConfigD3 = AbstractC4178x.d(databaseFieldConfigD2, "setId", 2, arrayList, databaseFieldConfigD2);
        DatabaseFieldConfig databaseFieldConfigD4 = AbstractC4178x.d(databaseFieldConfigD3, "personId", 2, arrayList, databaseFieldConfigD3);
        AbstractC4178x.q(databaseFieldConfigD4, "localId", "localGeneratedId", 2);
        DatabaseFieldConfig databaseFieldConfigF = AbstractC4178x.f(arrayList, databaseFieldConfigD4, "dirty", "dirty", 2);
        AbstractC4178x.q(databaseFieldConfigF, "isDeleted", "isDeleted", 2);
        DatabaseFieldConfig databaseFieldConfigF2 = AbstractC4178x.f(arrayList, databaseFieldConfigF, "lastModified", "lastModified", 2);
        AbstractC4178x.q(databaseFieldConfigF2, BaseDBModelFields.Names.CLIENT_TIMESTAMP, BaseDBModelFields.Names.CLIENT_TIMESTAMP, 2);
        arrayList.add(databaseFieldConfigF2);
        return arrayList;
    }

    public static DatabaseTableConfig<LegacyFavoriteSet> getTableConfig() {
        DatabaseTableConfig<LegacyFavoriteSet> databaseTableConfigG = AbstractC4178x.g(LegacyFavoriteSet.class, "favorite_set");
        databaseTableConfigG.setFieldConfigs(getFieldConfigs());
        return databaseTableConfigG;
    }
}

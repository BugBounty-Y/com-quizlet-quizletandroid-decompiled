package com.quizlet.db.data.models.legacy;

import com.j256.ormlite.field.DatabaseFieldConfig;
import com.j256.ormlite.table.DatabaseTableConfig;
import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.db.data.models.persisted.fields.BaseDBModelFields;
import java.util.ArrayList;
import java.util.List;

/* loaded from: classes2.dex */
public final class LegacyGroupWrapper$$Configuration {
    public static List<DatabaseFieldConfig> getFieldConfigs() {
        ArrayList arrayList = new ArrayList();
        DatabaseFieldConfig databaseFieldConfigE = AbstractC4178x.e("username", "username", true, 2, arrayList);
        DatabaseFieldConfig databaseFieldConfigD = AbstractC4178x.d(databaseFieldConfigE, "groupIds", 2, arrayList, databaseFieldConfigE);
        AbstractC4178x.q(databaseFieldConfigD, "localId", "localGeneratedId", 2);
        DatabaseFieldConfig databaseFieldConfigF = AbstractC4178x.f(arrayList, databaseFieldConfigD, "dirty", "dirty", 2);
        AbstractC4178x.q(databaseFieldConfigF, "isDeleted", "isDeleted", 2);
        DatabaseFieldConfig databaseFieldConfigF2 = AbstractC4178x.f(arrayList, databaseFieldConfigF, "lastModified", "lastModified", 2);
        AbstractC4178x.q(databaseFieldConfigF2, BaseDBModelFields.Names.CLIENT_TIMESTAMP, BaseDBModelFields.Names.CLIENT_TIMESTAMP, 2);
        arrayList.add(databaseFieldConfigF2);
        return arrayList;
    }

    public static DatabaseTableConfig<LegacyGroupWrapper> getTableConfig() {
        DatabaseTableConfig<LegacyGroupWrapper> databaseTableConfigG = AbstractC4178x.g(LegacyGroupWrapper.class, "group_wrapper");
        databaseTableConfigG.setFieldConfigs(getFieldConfigs());
        return databaseTableConfigG;
    }
}

package com.quizlet.db.data.models.legacy;

import com.j256.ormlite.field.DatabaseFieldConfig;
import com.j256.ormlite.table.DatabaseTableConfig;
import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.db.data.models.persisted.fields.BaseDBModelFields;
import java.util.ArrayList;
import java.util.List;

/* loaded from: classes2.dex */
public final class LegacyUser$$Configuration {
    public static List<DatabaseFieldConfig> getFieldConfigs() {
        ArrayList arrayList = new ArrayList();
        DatabaseFieldConfig databaseFieldConfigE = AbstractC4178x.e("username", "username", true, 2, arrayList);
        DatabaseFieldConfig databaseFieldConfigD = AbstractC4178x.d(databaseFieldConfigE, "signUpDate", 2, arrayList, databaseFieldConfigE);
        DatabaseFieldConfig databaseFieldConfigD2 = AbstractC4178x.d(databaseFieldConfigD, "profileImage", 2, arrayList, databaseFieldConfigD);
        AbstractC4178x.q(databaseFieldConfigD2, "id", "id", 2);
        arrayList.add(databaseFieldConfigD2);
        DatabaseFieldConfig databaseFieldConfig = new DatabaseFieldConfig();
        databaseFieldConfig.setFieldName("isTeacher");
        databaseFieldConfig.setMaxForeignAutoRefreshLevel(2);
        arrayList.add(databaseFieldConfig);
        DatabaseFieldConfig databaseFieldConfig2 = new DatabaseFieldConfig();
        databaseFieldConfig2.setFieldName("locked");
        DatabaseFieldConfig databaseFieldConfigC = AbstractC4178x.c(databaseFieldConfig2, 2, arrayList, databaseFieldConfig2, "language");
        DatabaseFieldConfig databaseFieldConfigC2 = AbstractC4178x.c(databaseFieldConfigC, 2, arrayList, databaseFieldConfigC, "localId");
        DatabaseFieldConfig databaseFieldConfigT = AbstractC4178x.t(databaseFieldConfigC2, 2, arrayList, databaseFieldConfigC2, "localGeneratedId");
        AbstractC4178x.q(databaseFieldConfigT, "dirty", "dirty", 2);
        DatabaseFieldConfig databaseFieldConfigF = AbstractC4178x.f(arrayList, databaseFieldConfigT, "isDeleted", "isDeleted", 2);
        AbstractC4178x.q(databaseFieldConfigF, "lastModified", "lastModified", 2);
        arrayList.add(databaseFieldConfigF);
        DatabaseFieldConfig databaseFieldConfig3 = new DatabaseFieldConfig();
        databaseFieldConfig3.setFieldName(BaseDBModelFields.Names.CLIENT_TIMESTAMP);
        databaseFieldConfig3.setColumnName(BaseDBModelFields.Names.CLIENT_TIMESTAMP);
        databaseFieldConfig3.setMaxForeignAutoRefreshLevel(2);
        arrayList.add(databaseFieldConfig3);
        return arrayList;
    }

    public static DatabaseTableConfig<LegacyUser> getTableConfig() {
        DatabaseTableConfig<LegacyUser> databaseTableConfigG = AbstractC4178x.g(LegacyUser.class, "legacy_user");
        databaseTableConfigG.setFieldConfigs(getFieldConfigs());
        return databaseTableConfigG;
    }
}

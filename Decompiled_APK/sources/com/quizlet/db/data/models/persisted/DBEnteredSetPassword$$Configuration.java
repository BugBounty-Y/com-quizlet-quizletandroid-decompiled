package com.quizlet.db.data.models.persisted;

import com.j256.ormlite.field.DatabaseFieldConfig;
import com.j256.ormlite.table.DatabaseTableConfig;
import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.db.data.models.persisted.fields.BaseDBModelFields;
import java.util.ArrayList;
import java.util.List;

/* loaded from: classes2.dex */
public final class DBEnteredSetPassword$$Configuration {
    public static List<DatabaseFieldConfig> getFieldConfigs() {
        ArrayList arrayList = new ArrayList();
        DatabaseFieldConfig databaseFieldConfigE = AbstractC4178x.e("id", "id", true, 2, arrayList);
        AbstractC4178x.q(databaseFieldConfigE, "localId", "localGeneratedId", 2);
        arrayList.add(databaseFieldConfigE);
        DatabaseFieldConfig databaseFieldConfig = new DatabaseFieldConfig();
        databaseFieldConfig.setFieldName("setId");
        databaseFieldConfig.setColumnName("setId");
        databaseFieldConfig.setUniqueCombo(true);
        DatabaseFieldConfig databaseFieldConfigC = AbstractC4178x.c(databaseFieldConfig, 2, arrayList, databaseFieldConfig, "personId");
        databaseFieldConfigC.setColumnName("personId");
        databaseFieldConfigC.setUniqueCombo(true);
        databaseFieldConfigC.setMaxForeignAutoRefreshLevel(2);
        arrayList.add(databaseFieldConfigC);
        DatabaseFieldConfig databaseFieldConfig2 = new DatabaseFieldConfig();
        databaseFieldConfig2.setFieldName("timestamp");
        databaseFieldConfig2.setMaxForeignAutoRefreshLevel(2);
        arrayList.add(databaseFieldConfig2);
        DatabaseFieldConfig databaseFieldConfig3 = new DatabaseFieldConfig();
        databaseFieldConfig3.setFieldName("dirty");
        DatabaseFieldConfig databaseFieldConfigT = AbstractC4178x.t(databaseFieldConfig3, 2, arrayList, databaseFieldConfig3, "dirty");
        AbstractC4178x.q(databaseFieldConfigT, "isDeleted", "isDeleted", 2);
        DatabaseFieldConfig databaseFieldConfigF = AbstractC4178x.f(arrayList, databaseFieldConfigT, "lastModified", "lastModified", 2);
        AbstractC4178x.q(databaseFieldConfigF, BaseDBModelFields.Names.CLIENT_TIMESTAMP, BaseDBModelFields.Names.CLIENT_TIMESTAMP, 2);
        arrayList.add(databaseFieldConfigF);
        return arrayList;
    }

    public static DatabaseTableConfig<DBEnteredSetPassword> getTableConfig() {
        DatabaseTableConfig<DBEnteredSetPassword> databaseTableConfigG = AbstractC4178x.g(DBEnteredSetPassword.class, DBEnteredSetPassword.TABLE_NAME);
        databaseTableConfigG.setFieldConfigs(getFieldConfigs());
        return databaseTableConfigG;
    }
}

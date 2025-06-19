package com.quizlet.db.data.models.persisted;

import com.j256.ormlite.field.DatabaseFieldConfig;
import com.j256.ormlite.table.DatabaseTableConfig;
import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.db.data.models.persisted.fields.BaseDBModelFields;
import java.util.ArrayList;
import java.util.List;

/* loaded from: classes2.dex */
public final class DBSelectedTerm$$Configuration {
    public static List<DatabaseFieldConfig> getFieldConfigs() {
        ArrayList arrayList = new ArrayList();
        DatabaseFieldConfig databaseFieldConfigE = AbstractC4178x.e("id", "id", true, 2, arrayList);
        AbstractC4178x.q(databaseFieldConfigE, "localId", "localGeneratedId", 2);
        arrayList.add(databaseFieldConfigE);
        DatabaseFieldConfig databaseFieldConfig = new DatabaseFieldConfig();
        databaseFieldConfig.setFieldName("termId");
        databaseFieldConfig.setColumnName("termId");
        databaseFieldConfig.setUniqueCombo(true);
        DatabaseFieldConfig databaseFieldConfigC = AbstractC4178x.c(databaseFieldConfig, 2, arrayList, databaseFieldConfig, "setId");
        DatabaseFieldConfig databaseFieldConfigT = AbstractC4178x.t(databaseFieldConfigC, 2, arrayList, databaseFieldConfigC, "setId");
        databaseFieldConfigT.setFieldName("personId");
        databaseFieldConfigT.setColumnName("personId");
        databaseFieldConfigT.setUniqueCombo(true);
        databaseFieldConfigT.setMaxForeignAutoRefreshLevel(2);
        arrayList.add(databaseFieldConfigT);
        DatabaseFieldConfig databaseFieldConfig2 = new DatabaseFieldConfig();
        databaseFieldConfig2.setFieldName("timestamp");
        databaseFieldConfig2.setMaxForeignAutoRefreshLevel(2);
        arrayList.add(databaseFieldConfig2);
        DatabaseFieldConfig databaseFieldConfig3 = new DatabaseFieldConfig();
        databaseFieldConfig3.setFieldName("source");
        DatabaseFieldConfig databaseFieldConfigC2 = AbstractC4178x.c(databaseFieldConfig3, 2, arrayList, databaseFieldConfig3, "dirty");
        DatabaseFieldConfig databaseFieldConfigT2 = AbstractC4178x.t(databaseFieldConfigC2, 2, arrayList, databaseFieldConfigC2, "dirty");
        AbstractC4178x.q(databaseFieldConfigT2, "isDeleted", "isDeleted", 2);
        DatabaseFieldConfig databaseFieldConfigF = AbstractC4178x.f(arrayList, databaseFieldConfigT2, "lastModified", "lastModified", 2);
        AbstractC4178x.q(databaseFieldConfigF, BaseDBModelFields.Names.CLIENT_TIMESTAMP, BaseDBModelFields.Names.CLIENT_TIMESTAMP, 2);
        arrayList.add(databaseFieldConfigF);
        return arrayList;
    }

    public static DatabaseTableConfig<DBSelectedTerm> getTableConfig() {
        DatabaseTableConfig<DBSelectedTerm> databaseTableConfigG = AbstractC4178x.g(DBSelectedTerm.class, DBSelectedTerm.TABLE_NAME);
        databaseTableConfigG.setFieldConfigs(getFieldConfigs());
        return databaseTableConfigG;
    }
}

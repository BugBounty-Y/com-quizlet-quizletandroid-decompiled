package com.quizlet.db.data.models.persisted;

import com.j256.ormlite.field.DatabaseFieldConfig;
import com.j256.ormlite.table.DatabaseTableConfig;
import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.db.data.models.persisted.fields.BaseDBModelFields;
import com.quizlet.db.data.models.persisted.fields.DBProgressResetFields;
import java.util.ArrayList;
import java.util.List;

/* loaded from: classes2.dex */
public final class DBProgressReset$$Configuration {
    public static List<DatabaseFieldConfig> getFieldConfigs() {
        ArrayList arrayList = new ArrayList();
        DatabaseFieldConfig databaseFieldConfigE = AbstractC4178x.e("localId", "localGeneratedId", true, 2, arrayList);
        databaseFieldConfigE.setFieldName("personId");
        databaseFieldConfigE.setColumnName("personId");
        databaseFieldConfigE.setUniqueCombo(true);
        databaseFieldConfigE.setMaxForeignAutoRefreshLevel(2);
        arrayList.add(databaseFieldConfigE);
        DatabaseFieldConfig databaseFieldConfig = new DatabaseFieldConfig();
        databaseFieldConfig.setFieldName(DBProgressResetFields.Names.CONTAINER_ID);
        databaseFieldConfig.setColumnName(DBProgressResetFields.Names.CONTAINER_ID);
        databaseFieldConfig.setUniqueCombo(true);
        DatabaseFieldConfig databaseFieldConfigC = AbstractC4178x.c(databaseFieldConfig, 2, arrayList, databaseFieldConfig, DBProgressResetFields.Names.CONTAINER_TYPE);
        databaseFieldConfigC.setColumnName(DBProgressResetFields.Names.CONTAINER_TYPE);
        databaseFieldConfigC.setUniqueCombo(true);
        databaseFieldConfigC.setMaxForeignAutoRefreshLevel(2);
        DatabaseFieldConfig databaseFieldConfigF = AbstractC4178x.f(arrayList, databaseFieldConfigC, DBProgressResetFields.Names.RESET_TIME_SEC, DBProgressResetFields.Names.RESET_TIME_SEC, 2);
        AbstractC4178x.q(databaseFieldConfigF, "dirty", "dirty", 2);
        DatabaseFieldConfig databaseFieldConfigF2 = AbstractC4178x.f(arrayList, databaseFieldConfigF, "isDeleted", "isDeleted", 2);
        AbstractC4178x.q(databaseFieldConfigF2, "lastModified", "lastModified", 2);
        arrayList.add(databaseFieldConfigF2);
        DatabaseFieldConfig databaseFieldConfig2 = new DatabaseFieldConfig();
        databaseFieldConfig2.setFieldName(BaseDBModelFields.Names.CLIENT_TIMESTAMP);
        databaseFieldConfig2.setColumnName(BaseDBModelFields.Names.CLIENT_TIMESTAMP);
        databaseFieldConfig2.setMaxForeignAutoRefreshLevel(2);
        arrayList.add(databaseFieldConfig2);
        return arrayList;
    }

    public static DatabaseTableConfig<DBProgressReset> getTableConfig() {
        DatabaseTableConfig<DBProgressReset> databaseTableConfigG = AbstractC4178x.g(DBProgressReset.class, DBProgressReset.TABLE_NAME);
        databaseTableConfigG.setFieldConfigs(getFieldConfigs());
        return databaseTableConfigG;
    }
}

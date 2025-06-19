package com.quizlet.db.data.models.persisted;

import com.j256.ormlite.field.DatabaseFieldConfig;
import com.j256.ormlite.table.DatabaseTableConfig;
import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.db.data.models.persisted.fields.BaseDBModelFields;
import com.quizlet.db.data.models.persisted.fields.DBOfflineEntityFields;
import java.util.ArrayList;
import java.util.List;

/* loaded from: classes2.dex */
public final class DBOfflineEntity$$Configuration {
    public static List<DatabaseFieldConfig> getFieldConfigs() {
        ArrayList arrayList = new ArrayList();
        DatabaseFieldConfig databaseFieldConfigE = AbstractC4178x.e("localId", "localGeneratedId", true, 2, arrayList);
        databaseFieldConfigE.setFieldName("savedModelId");
        databaseFieldConfigE.setColumnName(DBOfflineEntityFields.Names.MODEL_ID);
        databaseFieldConfigE.setUniqueCombo(true);
        databaseFieldConfigE.setMaxForeignAutoRefreshLevel(2);
        arrayList.add(databaseFieldConfigE);
        DatabaseFieldConfig databaseFieldConfig = new DatabaseFieldConfig();
        databaseFieldConfig.setFieldName("savedModelType");
        databaseFieldConfig.setColumnName(DBOfflineEntityFields.Names.MODEL_TYPE);
        databaseFieldConfig.setUniqueCombo(true);
        DatabaseFieldConfig databaseFieldConfigC = AbstractC4178x.c(databaseFieldConfig, 2, arrayList, databaseFieldConfig, "offlineStatus");
        DatabaseFieldConfig databaseFieldConfigT = AbstractC4178x.t(databaseFieldConfigC, 2, arrayList, databaseFieldConfigC, DBOfflineEntityFields.Names.OFFLINE_STATUS);
        AbstractC4178x.q(databaseFieldConfigT, "dirty", "dirty", 2);
        DatabaseFieldConfig databaseFieldConfigF = AbstractC4178x.f(arrayList, databaseFieldConfigT, "isDeleted", "isDeleted", 2);
        AbstractC4178x.q(databaseFieldConfigF, "lastModified", "lastModified", 2);
        arrayList.add(databaseFieldConfigF);
        DatabaseFieldConfig databaseFieldConfig2 = new DatabaseFieldConfig();
        databaseFieldConfig2.setFieldName(BaseDBModelFields.Names.CLIENT_TIMESTAMP);
        databaseFieldConfig2.setColumnName(BaseDBModelFields.Names.CLIENT_TIMESTAMP);
        databaseFieldConfig2.setMaxForeignAutoRefreshLevel(2);
        arrayList.add(databaseFieldConfig2);
        return arrayList;
    }

    public static DatabaseTableConfig<DBOfflineEntity> getTableConfig() {
        DatabaseTableConfig<DBOfflineEntity> databaseTableConfigG = AbstractC4178x.g(DBOfflineEntity.class, DBOfflineEntity.TABLE_NAME);
        databaseTableConfigG.setFieldConfigs(getFieldConfigs());
        return databaseTableConfigG;
    }
}

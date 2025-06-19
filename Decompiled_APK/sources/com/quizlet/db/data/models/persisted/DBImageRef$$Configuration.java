package com.quizlet.db.data.models.persisted;

import com.j256.ormlite.field.DatabaseFieldConfig;
import com.j256.ormlite.table.DatabaseTableConfig;
import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.db.data.models.persisted.fields.BaseDBModelFields;
import com.quizlet.db.data.models.persisted.fields.DBImageRefFields;
import java.util.ArrayList;
import java.util.List;

/* loaded from: classes2.dex */
public final class DBImageRef$$Configuration {
    public static List<DatabaseFieldConfig> getFieldConfigs() {
        ArrayList arrayList = new ArrayList();
        DatabaseFieldConfig databaseFieldConfigE = AbstractC4178x.e("id", "id", true, 2, arrayList);
        AbstractC4178x.q(databaseFieldConfigE, "localId", "localGeneratedId", 2);
        DatabaseFieldConfig databaseFieldConfigF = AbstractC4178x.f(arrayList, databaseFieldConfigE, DBImageRefFields.Names.MODEL_ID, DBImageRefFields.Names.MODEL_ID, 2);
        AbstractC4178x.q(databaseFieldConfigF, DBImageRefFields.Names.MODEL_TYPE, DBImageRefFields.Names.MODEL_TYPE, 2);
        DatabaseFieldConfig databaseFieldConfigF2 = AbstractC4178x.f(arrayList, databaseFieldConfigF, DBImageRefFields.Names.IMAGE_ID, DBImageRefFields.Names.IMAGE_ID, 2);
        AbstractC4178x.q(databaseFieldConfigF2, DBImageRefFields.Names.IMAGE_TYPE, DBImageRefFields.Names.IMAGE_TYPE, 2);
        DatabaseFieldConfig databaseFieldConfigF3 = AbstractC4178x.f(arrayList, databaseFieldConfigF2, "timestamp", "timestamp", 2);
        AbstractC4178x.q(databaseFieldConfigF3, "dirty", "dirty", 2);
        DatabaseFieldConfig databaseFieldConfigF4 = AbstractC4178x.f(arrayList, databaseFieldConfigF3, "isDeleted", "isDeleted", 2);
        AbstractC4178x.q(databaseFieldConfigF4, "lastModified", "lastModified", 2);
        arrayList.add(databaseFieldConfigF4);
        DatabaseFieldConfig databaseFieldConfig = new DatabaseFieldConfig();
        databaseFieldConfig.setFieldName(BaseDBModelFields.Names.CLIENT_TIMESTAMP);
        databaseFieldConfig.setColumnName(BaseDBModelFields.Names.CLIENT_TIMESTAMP);
        databaseFieldConfig.setMaxForeignAutoRefreshLevel(2);
        arrayList.add(databaseFieldConfig);
        return arrayList;
    }

    public static DatabaseTableConfig<DBImageRef> getTableConfig() {
        DatabaseTableConfig<DBImageRef> databaseTableConfigG = AbstractC4178x.g(DBImageRef.class, DBImageRef.TABLE_NAME);
        databaseTableConfigG.setFieldConfigs(getFieldConfigs());
        return databaseTableConfigG;
    }
}

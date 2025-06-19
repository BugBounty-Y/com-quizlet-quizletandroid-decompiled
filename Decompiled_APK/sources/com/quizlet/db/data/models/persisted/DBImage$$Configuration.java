package com.quizlet.db.data.models.persisted;

import com.j256.ormlite.field.DatabaseFieldConfig;
import com.j256.ormlite.table.DatabaseTableConfig;
import com.onetrust.otpublishers.headless.Public.Keys.OTUXParamsKeys;
import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.db.data.models.persisted.fields.BaseDBModelFields;
import com.quizlet.db.data.models.persisted.fields.DBImageFields;
import java.util.ArrayList;
import java.util.List;

/* loaded from: classes2.dex */
public final class DBImage$$Configuration {
    public static List<DatabaseFieldConfig> getFieldConfigs() {
        ArrayList arrayList = new ArrayList();
        DatabaseFieldConfig databaseFieldConfigE = AbstractC4178x.e("id", "id", true, 2, arrayList);
        AbstractC4178x.q(databaseFieldConfigE, "localId", "localGeneratedId", 2);
        arrayList.add(databaseFieldConfigE);
        DatabaseFieldConfig databaseFieldConfig = new DatabaseFieldConfig();
        databaseFieldConfig.setFieldName("personId");
        databaseFieldConfig.setMaxForeignAutoRefreshLevel(2);
        arrayList.add(databaseFieldConfig);
        DatabaseFieldConfig databaseFieldConfig2 = new DatabaseFieldConfig();
        databaseFieldConfig2.setFieldName("timestamp");
        DatabaseFieldConfig databaseFieldConfigC = AbstractC4178x.c(databaseFieldConfig2, 2, arrayList, databaseFieldConfig2, "code");
        DatabaseFieldConfig databaseFieldConfigC2 = AbstractC4178x.c(databaseFieldConfigC, 2, arrayList, databaseFieldConfigC, OTUXParamsKeys.OT_UX_WIDTH);
        DatabaseFieldConfig databaseFieldConfigC3 = AbstractC4178x.c(databaseFieldConfigC2, 2, arrayList, databaseFieldConfigC2, OTUXParamsKeys.OT_UX_HEIGHT);
        DatabaseFieldConfig databaseFieldConfigC4 = AbstractC4178x.c(databaseFieldConfigC3, 2, arrayList, databaseFieldConfigC3, DBImageFields.Names.SQUARE_URL);
        DatabaseFieldConfig databaseFieldConfigT = AbstractC4178x.t(databaseFieldConfigC4, 2, arrayList, databaseFieldConfigC4, DBImageFields.Names.SQUARE_URL);
        AbstractC4178x.q(databaseFieldConfigT, DBImageFields.Names.SMALL_URL, DBImageFields.Names.SMALL_URL, 2);
        DatabaseFieldConfig databaseFieldConfigF = AbstractC4178x.f(arrayList, databaseFieldConfigT, DBImageFields.Names.MEDIUM_URL, DBImageFields.Names.MEDIUM_URL, 2);
        AbstractC4178x.q(databaseFieldConfigF, DBImageFields.Names.LARGE_URL, DBImageFields.Names.LARGE_URL, 2);
        DatabaseFieldConfig databaseFieldConfigF2 = AbstractC4178x.f(arrayList, databaseFieldConfigF, DBImageFields.Names.LOCAL_PATH, DBImageFields.Names.LOCAL_PATH, 2);
        AbstractC4178x.q(databaseFieldConfigF2, "dirty", "dirty", 2);
        DatabaseFieldConfig databaseFieldConfigF3 = AbstractC4178x.f(arrayList, databaseFieldConfigF2, "isDeleted", "isDeleted", 2);
        AbstractC4178x.q(databaseFieldConfigF3, "lastModified", "lastModified", 2);
        arrayList.add(databaseFieldConfigF3);
        DatabaseFieldConfig databaseFieldConfig3 = new DatabaseFieldConfig();
        databaseFieldConfig3.setFieldName(BaseDBModelFields.Names.CLIENT_TIMESTAMP);
        databaseFieldConfig3.setColumnName(BaseDBModelFields.Names.CLIENT_TIMESTAMP);
        databaseFieldConfig3.setMaxForeignAutoRefreshLevel(2);
        arrayList.add(databaseFieldConfig3);
        return arrayList;
    }

    public static DatabaseTableConfig<DBImage> getTableConfig() {
        DatabaseTableConfig<DBImage> databaseTableConfigG = AbstractC4178x.g(DBImage.class, "image");
        databaseTableConfigG.setFieldConfigs(getFieldConfigs());
        return databaseTableConfigG;
    }
}

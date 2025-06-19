package com.quizlet.db.data.models.persisted;

import com.j256.ormlite.field.DatabaseFieldConfig;
import com.j256.ormlite.table.DatabaseTableConfig;
import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.db.data.models.persisted.fields.BaseDBModelFields;
import com.quizlet.db.data.models.persisted.fields.DBGroupMembershipFields;
import java.util.ArrayList;
import java.util.List;

/* loaded from: classes2.dex */
public final class DBGroupMembership$$Configuration {
    public static List<DatabaseFieldConfig> getFieldConfigs() {
        ArrayList arrayList = new ArrayList();
        DatabaseFieldConfig databaseFieldConfigE = AbstractC4178x.e("id", "id", true, 2, arrayList);
        AbstractC4178x.q(databaseFieldConfigE, "localId", "localGeneratedId", 2);
        arrayList.add(databaseFieldConfigE);
        DatabaseFieldConfig databaseFieldConfig = new DatabaseFieldConfig();
        databaseFieldConfig.setFieldName(DBGroupMembershipFields.Names.CLASS_ID);
        databaseFieldConfig.setColumnName(DBGroupMembershipFields.Names.CLASS_ID);
        databaseFieldConfig.setUniqueCombo(true);
        DatabaseFieldConfig databaseFieldConfigC = AbstractC4178x.c(databaseFieldConfig, 2, arrayList, databaseFieldConfig, "userId");
        databaseFieldConfigC.setColumnName("userId");
        databaseFieldConfigC.setUniqueCombo(true);
        databaseFieldConfigC.setMaxForeignAutoRefreshLevel(2);
        arrayList.add(databaseFieldConfigC);
        DatabaseFieldConfig databaseFieldConfig2 = new DatabaseFieldConfig();
        databaseFieldConfig2.setFieldName("level");
        databaseFieldConfig2.setMaxForeignAutoRefreshLevel(2);
        arrayList.add(databaseFieldConfig2);
        DatabaseFieldConfig databaseFieldConfig3 = new DatabaseFieldConfig();
        databaseFieldConfig3.setFieldName("receiveEmail");
        DatabaseFieldConfig databaseFieldConfigC2 = AbstractC4178x.c(databaseFieldConfig3, 2, arrayList, databaseFieldConfig3, "lastVisited");
        DatabaseFieldConfig databaseFieldConfigC3 = AbstractC4178x.c(databaseFieldConfigC2, 2, arrayList, databaseFieldConfigC2, "timestamp");
        DatabaseFieldConfig databaseFieldConfigC4 = AbstractC4178x.c(databaseFieldConfigC3, 2, arrayList, databaseFieldConfigC3, "dirty");
        DatabaseFieldConfig databaseFieldConfigT = AbstractC4178x.t(databaseFieldConfigC4, 2, arrayList, databaseFieldConfigC4, "dirty");
        AbstractC4178x.q(databaseFieldConfigT, "isDeleted", "isDeleted", 2);
        DatabaseFieldConfig databaseFieldConfigF = AbstractC4178x.f(arrayList, databaseFieldConfigT, "lastModified", "lastModified", 2);
        AbstractC4178x.q(databaseFieldConfigF, BaseDBModelFields.Names.CLIENT_TIMESTAMP, BaseDBModelFields.Names.CLIENT_TIMESTAMP, 2);
        arrayList.add(databaseFieldConfigF);
        return arrayList;
    }

    public static DatabaseTableConfig<DBGroupMembership> getTableConfig() {
        DatabaseTableConfig<DBGroupMembership> databaseTableConfigG = AbstractC4178x.g(DBGroupMembership.class, DBGroupMembership.TABLE_NAME);
        databaseTableConfigG.setFieldConfigs(getFieldConfigs());
        return databaseTableConfigG;
    }
}

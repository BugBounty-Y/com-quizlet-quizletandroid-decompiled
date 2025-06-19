package com.quizlet.db.data.models.legacy;

import com.j256.ormlite.field.DatabaseFieldConfig;
import com.j256.ormlite.table.DatabaseTableConfig;
import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.db.data.models.persisted.fields.BaseDBModelFields;
import java.util.ArrayList;
import java.util.List;

/* loaded from: classes2.dex */
public final class LegacyGroupMembership$$Configuration {
    public static List<DatabaseFieldConfig> getFieldConfigs() {
        ArrayList arrayList = new ArrayList();
        DatabaseFieldConfig databaseFieldConfigE = AbstractC4178x.e("membershipId", "membershipId", true, 2, arrayList);
        AbstractC4178x.q(databaseFieldConfigE, "groupId", "groupId", 2);
        arrayList.add(databaseFieldConfigE);
        DatabaseFieldConfig databaseFieldConfig = new DatabaseFieldConfig();
        databaseFieldConfig.setFieldName("username");
        databaseFieldConfig.setMaxForeignAutoRefreshLevel(2);
        arrayList.add(databaseFieldConfig);
        DatabaseFieldConfig databaseFieldConfig2 = new DatabaseFieldConfig();
        databaseFieldConfig2.setFieldName("profileImage");
        DatabaseFieldConfig databaseFieldConfigC = AbstractC4178x.c(databaseFieldConfig2, 2, arrayList, databaseFieldConfig2, "role");
        DatabaseFieldConfig databaseFieldConfigC2 = AbstractC4178x.c(databaseFieldConfigC, 2, arrayList, databaseFieldConfigC, "emailNotification");
        DatabaseFieldConfig databaseFieldConfigC3 = AbstractC4178x.c(databaseFieldConfigC2, 2, arrayList, databaseFieldConfigC2, "localId");
        DatabaseFieldConfig databaseFieldConfigT = AbstractC4178x.t(databaseFieldConfigC3, 2, arrayList, databaseFieldConfigC3, "localGeneratedId");
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

    public static DatabaseTableConfig<LegacyGroupMembership> getTableConfig() {
        DatabaseTableConfig<LegacyGroupMembership> databaseTableConfigG = AbstractC4178x.g(LegacyGroupMembership.class, "legacy_group_membership");
        databaseTableConfigG.setFieldConfigs(getFieldConfigs());
        return databaseTableConfigG;
    }
}

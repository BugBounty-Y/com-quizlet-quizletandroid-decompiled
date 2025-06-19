package com.quizlet.db.data.models.persisted;

import com.j256.ormlite.field.DatabaseFieldConfig;
import com.j256.ormlite.table.DatabaseTableConfig;
import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.db.data.models.persisted.fields.BaseDBModelFields;
import com.quizlet.db.data.models.persisted.fields.DBGroupFolderFields;
import com.quizlet.db.data.models.persisted.fields.DBGroupMembershipFields;
import com.quizlet.db.data.models.persisted.fields.DBGroupSetFields;
import java.util.ArrayList;
import java.util.List;

/* loaded from: classes2.dex */
public final class DBGroupSet$$Configuration {
    public static List<DatabaseFieldConfig> getFieldConfigs() {
        ArrayList arrayList = new ArrayList();
        DatabaseFieldConfig databaseFieldConfig = new DatabaseFieldConfig();
        databaseFieldConfig.setFieldName("userId");
        databaseFieldConfig.setColumnName("userId");
        databaseFieldConfig.setMaxForeignAutoRefreshLevel(2);
        arrayList.add(databaseFieldConfig);
        DatabaseFieldConfig databaseFieldConfig2 = new DatabaseFieldConfig();
        databaseFieldConfig2.setFieldName(DBGroupFolderFields.Names.CAN_EDIT);
        DatabaseFieldConfig databaseFieldConfigC = AbstractC4178x.c(databaseFieldConfig2, 2, arrayList, databaseFieldConfig2, "timestamp");
        DatabaseFieldConfig databaseFieldConfigT = AbstractC4178x.t(databaseFieldConfigC, 2, arrayList, databaseFieldConfigC, DBGroupSetFields.Names.TIMESTAMP);
        databaseFieldConfigT.setFieldName("id");
        databaseFieldConfigT.setColumnName("id");
        databaseFieldConfigT.setId(true);
        databaseFieldConfigT.setMaxForeignAutoRefreshLevel(2);
        DatabaseFieldConfig databaseFieldConfigF = AbstractC4178x.f(arrayList, databaseFieldConfigT, "localId", "localGeneratedId", 2);
        databaseFieldConfigF.setFieldName(DBGroupMembershipFields.Names.CLASS_ID);
        databaseFieldConfigF.setColumnName("groupId");
        databaseFieldConfigF.setUniqueCombo(true);
        databaseFieldConfigF.setMaxForeignAutoRefreshLevel(2);
        arrayList.add(databaseFieldConfigF);
        DatabaseFieldConfig databaseFieldConfig3 = new DatabaseFieldConfig();
        databaseFieldConfig3.setFieldName("setId");
        databaseFieldConfig3.setColumnName("setId");
        databaseFieldConfig3.setUniqueCombo(true);
        DatabaseFieldConfig databaseFieldConfigC2 = AbstractC4178x.c(databaseFieldConfig3, 2, arrayList, databaseFieldConfig3, "folderId");
        DatabaseFieldConfig databaseFieldConfigT2 = AbstractC4178x.t(databaseFieldConfigC2, 2, arrayList, databaseFieldConfigC2, "folderId");
        AbstractC4178x.q(databaseFieldConfigT2, "dirty", "dirty", 2);
        DatabaseFieldConfig databaseFieldConfigF2 = AbstractC4178x.f(arrayList, databaseFieldConfigT2, "isDeleted", "isDeleted", 2);
        AbstractC4178x.q(databaseFieldConfigF2, "lastModified", "lastModified", 2);
        arrayList.add(databaseFieldConfigF2);
        DatabaseFieldConfig databaseFieldConfig4 = new DatabaseFieldConfig();
        databaseFieldConfig4.setFieldName(BaseDBModelFields.Names.CLIENT_TIMESTAMP);
        databaseFieldConfig4.setColumnName(BaseDBModelFields.Names.CLIENT_TIMESTAMP);
        databaseFieldConfig4.setMaxForeignAutoRefreshLevel(2);
        arrayList.add(databaseFieldConfig4);
        return arrayList;
    }

    public static DatabaseTableConfig<DBGroupSet> getTableConfig() {
        DatabaseTableConfig<DBGroupSet> databaseTableConfigG = AbstractC4178x.g(DBGroupSet.class, DBGroupSet.TABLE_NAME);
        databaseTableConfigG.setFieldConfigs(getFieldConfigs());
        return databaseTableConfigG;
    }
}

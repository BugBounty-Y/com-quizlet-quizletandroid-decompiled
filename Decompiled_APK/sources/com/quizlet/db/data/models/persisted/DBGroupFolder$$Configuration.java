package com.quizlet.db.data.models.persisted;

import com.j256.ormlite.field.DatabaseFieldConfig;
import com.j256.ormlite.table.DatabaseTableConfig;
import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.db.data.models.persisted.fields.BaseDBModelFields;
import com.quizlet.db.data.models.persisted.fields.DBGroupFolderFields;
import com.quizlet.db.data.models.persisted.fields.DBGroupMembershipFields;
import java.util.ArrayList;
import java.util.List;

/* loaded from: classes2.dex */
public final class DBGroupFolder$$Configuration {
    public static List<DatabaseFieldConfig> getFieldConfigs() {
        ArrayList arrayList = new ArrayList();
        DatabaseFieldConfig databaseFieldConfigE = AbstractC4178x.e("localId", "localGeneratedId", true, 2, arrayList);
        databaseFieldConfigE.setFieldName(DBGroupMembershipFields.Names.CLASS_ID);
        databaseFieldConfigE.setColumnName("groupId");
        databaseFieldConfigE.setUniqueCombo(true);
        databaseFieldConfigE.setMaxForeignAutoRefreshLevel(2);
        arrayList.add(databaseFieldConfigE);
        DatabaseFieldConfig databaseFieldConfig = new DatabaseFieldConfig();
        databaseFieldConfig.setFieldName("folderId");
        databaseFieldConfig.setColumnName("folderId");
        databaseFieldConfig.setUniqueCombo(true);
        DatabaseFieldConfig databaseFieldConfigC = AbstractC4178x.c(databaseFieldConfig, 2, arrayList, databaseFieldConfig, DBGroupFolderFields.Names.CAN_EDIT);
        DatabaseFieldConfig databaseFieldConfigT = AbstractC4178x.t(databaseFieldConfigC, 2, arrayList, databaseFieldConfigC, DBGroupFolderFields.Names.CAN_EDIT);
        AbstractC4178x.q(databaseFieldConfigT, "timestamp", "timestamp", 2);
        DatabaseFieldConfig databaseFieldConfigF = AbstractC4178x.f(arrayList, databaseFieldConfigT, "dirty", "dirty", 2);
        AbstractC4178x.q(databaseFieldConfigF, "isDeleted", "isDeleted", 2);
        DatabaseFieldConfig databaseFieldConfigF2 = AbstractC4178x.f(arrayList, databaseFieldConfigF, "lastModified", "lastModified", 2);
        AbstractC4178x.q(databaseFieldConfigF2, BaseDBModelFields.Names.CLIENT_TIMESTAMP, BaseDBModelFields.Names.CLIENT_TIMESTAMP, 2);
        arrayList.add(databaseFieldConfigF2);
        return arrayList;
    }

    public static DatabaseTableConfig<DBGroupFolder> getTableConfig() {
        DatabaseTableConfig<DBGroupFolder> databaseTableConfigG = AbstractC4178x.g(DBGroupFolder.class, DBGroupFolder.TABLE_NAME);
        databaseTableConfigG.setFieldConfigs(getFieldConfigs());
        return databaseTableConfigG;
    }
}

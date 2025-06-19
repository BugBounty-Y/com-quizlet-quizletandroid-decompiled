package com.quizlet.db.data.models.persisted;

import com.j256.ormlite.field.DatabaseFieldConfig;
import com.j256.ormlite.table.DatabaseTableConfig;
import com.onetrust.otpublishers.headless.Public.Keys.OTUXParamsKeys;
import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.db.data.models.persisted.fields.BaseDBModelFields;
import com.quizlet.db.data.models.persisted.fields.DBGroupFields;
import com.quizlet.db.data.models.persisted.fields.DBStudySetFields;
import java.util.ArrayList;
import java.util.List;

/* loaded from: classes2.dex */
public final class DBGroup$$Configuration {
    public static List<DatabaseFieldConfig> getFieldConfigs() {
        ArrayList arrayList = new ArrayList();
        DatabaseFieldConfig databaseFieldConfigE = AbstractC4178x.e("id", "id", true, 2, arrayList);
        AbstractC4178x.q(databaseFieldConfigE, "localId", "localGeneratedId", 2);
        arrayList.add(databaseFieldConfigE);
        DatabaseFieldConfig databaseFieldConfig = new DatabaseFieldConfig();
        databaseFieldConfig.setFieldName("name");
        databaseFieldConfig.setMaxForeignAutoRefreshLevel(2);
        arrayList.add(databaseFieldConfig);
        DatabaseFieldConfig databaseFieldConfig2 = new DatabaseFieldConfig();
        databaseFieldConfig2.setFieldName(OTUXParamsKeys.OT_UX_DESCRIPTION);
        DatabaseFieldConfig databaseFieldConfigC = AbstractC4178x.c(databaseFieldConfig2, 2, arrayList, databaseFieldConfig2, DBStudySetFields.Names.TIMESTAMP);
        DatabaseFieldConfig databaseFieldConfigC2 = AbstractC4178x.c(databaseFieldConfigC, 2, arrayList, databaseFieldConfigC, "adminOnly");
        DatabaseFieldConfig databaseFieldConfigC3 = AbstractC4178x.c(databaseFieldConfigC2, 2, arrayList, databaseFieldConfigC2, DBGroupFields.Names.SCHOOL_ID);
        DatabaseFieldConfig databaseFieldConfigT = AbstractC4178x.t(databaseFieldConfigC3, 2, arrayList, databaseFieldConfigC3, DBGroupFields.Names.SCHOOL_ID);
        AbstractC4178x.q(databaseFieldConfigT, "creatorId", "creatorId", 2);
        DatabaseFieldConfig databaseFieldConfigF = AbstractC4178x.f(arrayList, databaseFieldConfigT, DBGroupFields.Names.AUTO_JOIN_LINK, DBGroupFields.Names.AUTO_JOIN_LINK, 2);
        AbstractC4178x.q(databaseFieldConfigF, "numSets", DBGroupFields.Names.NUM_SETS, 2);
        DatabaseFieldConfig databaseFieldConfigF2 = AbstractC4178x.f(arrayList, databaseFieldConfigF, "numMembers", DBGroupFields.Names.NUM_MEMBERS, 2);
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

    public static DatabaseTableConfig<DBGroup> getTableConfig() {
        DatabaseTableConfig<DBGroup> databaseTableConfigG = AbstractC4178x.g(DBGroup.class, DBGroup.TABLE_NAME);
        databaseTableConfigG.setFieldConfigs(getFieldConfigs());
        return databaseTableConfigG;
    }
}

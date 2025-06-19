package com.quizlet.db.data.models.persisted;

import com.j256.ormlite.field.DatabaseFieldConfig;
import com.j256.ormlite.table.DatabaseTableConfig;
import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.db.data.models.persisted.fields.BaseDBModelFields;
import com.quizlet.db.data.models.persisted.fields.DBSessionFields;
import com.quizlet.db.data.models.persisted.fields.DBUserFields;
import java.util.ArrayList;
import java.util.List;

/* loaded from: classes2.dex */
public final class DBSession$$Configuration {
    public static List<DatabaseFieldConfig> getFieldConfigs() {
        ArrayList arrayList = new ArrayList();
        DatabaseFieldConfig databaseFieldConfigE = AbstractC4178x.e("id", "id", true, 2, arrayList);
        AbstractC4178x.q(databaseFieldConfigE, "localId", "localGeneratedId", 2);
        DatabaseFieldConfig databaseFieldConfigF = AbstractC4178x.f(arrayList, databaseFieldConfigE, DBSessionFields.Names.ITEM_TYPE, DBSessionFields.Names.ITEM_TYPE, 2);
        AbstractC4178x.q(databaseFieldConfigF, DBSessionFields.Names.ITEM_ID, DBSessionFields.Names.ITEM_ID, 2);
        DatabaseFieldConfig databaseFieldConfigF2 = AbstractC4178x.f(arrayList, databaseFieldConfigF, "personId", "personId", 2);
        AbstractC4178x.q(databaseFieldConfigF2, "timestamp", "startTimestamp", 2);
        DatabaseFieldConfig databaseFieldConfigF3 = AbstractC4178x.f(arrayList, databaseFieldConfigF2, "endedTimestamp", DBSessionFields.Names.ENDED_TIMESTAMP, 2);
        AbstractC4178x.q(databaseFieldConfigF3, DBUserFields.Names.USER_UPGRADE_TYPE, "mode", 2);
        DatabaseFieldConfig databaseFieldConfigF4 = AbstractC4178x.f(arrayList, databaseFieldConfigF3, DBSessionFields.Names.SCORE, DBSessionFields.Names.SCORE, 2);
        AbstractC4178x.q(databaseFieldConfigF4, "selectedTermsOnly", DBSessionFields.Names.SELECTED_TERMS_ONLY, 2);
        arrayList.add(databaseFieldConfigF4);
        DatabaseFieldConfig databaseFieldConfig = new DatabaseFieldConfig();
        databaseFieldConfig.setFieldName("hidden");
        databaseFieldConfig.setMaxForeignAutoRefreshLevel(2);
        arrayList.add(databaseFieldConfig);
        DatabaseFieldConfig databaseFieldConfig2 = new DatabaseFieldConfig();
        databaseFieldConfig2.setFieldName("dirty");
        DatabaseFieldConfig databaseFieldConfigT = AbstractC4178x.t(databaseFieldConfig2, 2, arrayList, databaseFieldConfig2, "dirty");
        AbstractC4178x.q(databaseFieldConfigT, "isDeleted", "isDeleted", 2);
        DatabaseFieldConfig databaseFieldConfigF5 = AbstractC4178x.f(arrayList, databaseFieldConfigT, "lastModified", "lastModified", 2);
        AbstractC4178x.q(databaseFieldConfigF5, BaseDBModelFields.Names.CLIENT_TIMESTAMP, BaseDBModelFields.Names.CLIENT_TIMESTAMP, 2);
        arrayList.add(databaseFieldConfigF5);
        return arrayList;
    }

    public static DatabaseTableConfig<DBSession> getTableConfig() {
        DatabaseTableConfig<DBSession> databaseTableConfigG = AbstractC4178x.g(DBSession.class, "session");
        databaseTableConfigG.setFieldConfigs(getFieldConfigs());
        return databaseTableConfigG;
    }
}

package com.quizlet.db.data.models.persisted;

import com.j256.ormlite.field.DatabaseFieldConfig;
import com.j256.ormlite.table.DatabaseTableConfig;
import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.db.data.models.persisted.fields.BaseDBModelFields;
import com.quizlet.db.data.models.persisted.fields.DBAnswerFields;
import com.quizlet.db.data.models.persisted.fields.DBUserFields;
import java.util.ArrayList;
import java.util.List;

/* loaded from: classes2.dex */
public final class DBAnswer$$Configuration {
    public static List<DatabaseFieldConfig> getFieldConfigs() {
        ArrayList arrayList = new ArrayList();
        DatabaseFieldConfig databaseFieldConfigE = AbstractC4178x.e("id", "id", true, 2, arrayList);
        AbstractC4178x.q(databaseFieldConfigE, "localId", "localGeneratedId", 2);
        DatabaseFieldConfig databaseFieldConfigF = AbstractC4178x.f(arrayList, databaseFieldConfigE, "termId", "termId", 2);
        AbstractC4178x.q(databaseFieldConfigF, DBAnswerFields.Names.SESSION_ID, DBAnswerFields.Names.SESSION_ID, 2);
        DatabaseFieldConfig databaseFieldConfigF2 = AbstractC4178x.f(arrayList, databaseFieldConfigF, "setId", "setId", 2);
        AbstractC4178x.q(databaseFieldConfigF2, "personId", "personId", 2);
        DatabaseFieldConfig databaseFieldConfigF3 = AbstractC4178x.f(arrayList, databaseFieldConfigF2, DBUserFields.Names.USER_UPGRADE_TYPE, "mode", 2);
        DatabaseFieldConfig databaseFieldConfigD = AbstractC4178x.d(databaseFieldConfigF3, "round", 2, arrayList, databaseFieldConfigF3);
        AbstractC4178x.q(databaseFieldConfigD, DBAnswerFields.Names.CORRECTNESS, DBAnswerFields.Names.CORRECTNESS, 2);
        arrayList.add(databaseFieldConfigD);
        DatabaseFieldConfig databaseFieldConfig = new DatabaseFieldConfig();
        databaseFieldConfig.setFieldName("timestamp");
        databaseFieldConfig.setMaxForeignAutoRefreshLevel(2);
        arrayList.add(databaseFieldConfig);
        DatabaseFieldConfig databaseFieldConfig2 = new DatabaseFieldConfig();
        databaseFieldConfig2.setFieldName("promptSide");
        DatabaseFieldConfig databaseFieldConfigC = AbstractC4178x.c(databaseFieldConfig2, 2, arrayList, databaseFieldConfig2, "dirty");
        DatabaseFieldConfig databaseFieldConfigT = AbstractC4178x.t(databaseFieldConfigC, 2, arrayList, databaseFieldConfigC, "dirty");
        AbstractC4178x.q(databaseFieldConfigT, "isDeleted", "isDeleted", 2);
        DatabaseFieldConfig databaseFieldConfigF4 = AbstractC4178x.f(arrayList, databaseFieldConfigT, "lastModified", "lastModified", 2);
        AbstractC4178x.q(databaseFieldConfigF4, BaseDBModelFields.Names.CLIENT_TIMESTAMP, BaseDBModelFields.Names.CLIENT_TIMESTAMP, 2);
        arrayList.add(databaseFieldConfigF4);
        return arrayList;
    }

    public static DatabaseTableConfig<DBAnswer> getTableConfig() {
        DatabaseTableConfig<DBAnswer> databaseTableConfigG = AbstractC4178x.g(DBAnswer.class, "answer");
        databaseTableConfigG.setFieldConfigs(getFieldConfigs());
        return databaseTableConfigG;
    }
}

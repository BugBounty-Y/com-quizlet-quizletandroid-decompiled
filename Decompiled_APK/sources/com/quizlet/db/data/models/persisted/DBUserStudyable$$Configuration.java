package com.quizlet.db.data.models.persisted;

import com.j256.ormlite.field.DatabaseFieldConfig;
import com.j256.ormlite.table.DatabaseTableConfig;
import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.db.data.models.persisted.fields.BaseDBModelFields;
import com.quizlet.db.data.models.persisted.fields.DBUserStudyableFields;
import java.util.ArrayList;
import java.util.List;

/* loaded from: classes2.dex */
public final class DBUserStudyable$$Configuration {
    public static List<DatabaseFieldConfig> getFieldConfigs() {
        ArrayList arrayList = new ArrayList();
        DatabaseFieldConfig databaseFieldConfigE = AbstractC4178x.e("localId", "localGeneratedId", true, 2, arrayList);
        databaseFieldConfigE.setFieldName("personId");
        databaseFieldConfigE.setColumnName("personId");
        databaseFieldConfigE.setUniqueCombo(true);
        databaseFieldConfigE.setMaxForeignAutoRefreshLevel(2);
        arrayList.add(databaseFieldConfigE);
        DatabaseFieldConfig databaseFieldConfig = new DatabaseFieldConfig();
        databaseFieldConfig.setFieldName(DBUserStudyableFields.Names.STUDYABLE_TYPE);
        databaseFieldConfig.setColumnName(DBUserStudyableFields.Names.STUDYABLE_TYPE);
        databaseFieldConfig.setUniqueCombo(true);
        DatabaseFieldConfig databaseFieldConfigC = AbstractC4178x.c(databaseFieldConfig, 2, arrayList, databaseFieldConfig, DBUserStudyableFields.Names.STUDYABLE_ID);
        databaseFieldConfigC.setColumnName(DBUserStudyableFields.Names.STUDYABLE_ID);
        databaseFieldConfigC.setUniqueCombo(true);
        databaseFieldConfigC.setMaxForeignAutoRefreshLevel(2);
        DatabaseFieldConfig databaseFieldConfigF = AbstractC4178x.f(arrayList, databaseFieldConfigC, "startTimestampSec", "startTimestamp", 2);
        AbstractC4178x.q(databaseFieldConfigF, "dueTimestampSec", DBUserStudyableFields.Names.DUE_TIMESTAMP, 2);
        DatabaseFieldConfig databaseFieldConfigF2 = AbstractC4178x.f(arrayList, databaseFieldConfigF, DBUserStudyableFields.Names.NOTIFICATION_STATUS, DBUserStudyableFields.Names.NOTIFICATION_STATUS, 2);
        AbstractC4178x.q(databaseFieldConfigF2, "timestamp", "timestamp", 2);
        DatabaseFieldConfig databaseFieldConfigF3 = AbstractC4178x.f(arrayList, databaseFieldConfigF2, DBUserStudyableFields.Names.IS_ACTIVE, DBUserStudyableFields.Names.IS_ACTIVE, 2);
        AbstractC4178x.q(databaseFieldConfigF3, DBUserStudyableFields.Names.LAST_STUDIED_TIMESTAMP, DBUserStudyableFields.Names.LAST_STUDIED_TIMESTAMP, 2);
        DatabaseFieldConfig databaseFieldConfigF4 = AbstractC4178x.f(arrayList, databaseFieldConfigF3, DBUserStudyableFields.Names.IS_DISMISSED, DBUserStudyableFields.Names.IS_DISMISSED, 2);
        AbstractC4178x.q(databaseFieldConfigF4, "dirty", "dirty", 2);
        DatabaseFieldConfig databaseFieldConfigF5 = AbstractC4178x.f(arrayList, databaseFieldConfigF4, "isDeleted", "isDeleted", 2);
        AbstractC4178x.q(databaseFieldConfigF5, "lastModified", "lastModified", 2);
        arrayList.add(databaseFieldConfigF5);
        DatabaseFieldConfig databaseFieldConfig2 = new DatabaseFieldConfig();
        databaseFieldConfig2.setFieldName(BaseDBModelFields.Names.CLIENT_TIMESTAMP);
        databaseFieldConfig2.setColumnName(BaseDBModelFields.Names.CLIENT_TIMESTAMP);
        databaseFieldConfig2.setMaxForeignAutoRefreshLevel(2);
        arrayList.add(databaseFieldConfig2);
        return arrayList;
    }

    public static DatabaseTableConfig<DBUserStudyable> getTableConfig() {
        DatabaseTableConfig<DBUserStudyable> databaseTableConfigG = AbstractC4178x.g(DBUserStudyable.class, DBUserStudyable.TABLE_NAME);
        databaseTableConfigG.setFieldConfigs(getFieldConfigs());
        return databaseTableConfigG;
    }
}

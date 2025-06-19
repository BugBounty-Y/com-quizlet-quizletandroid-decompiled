package com.quizlet.db.data.models.persisted;

import com.j256.ormlite.field.DatabaseFieldConfig;
import com.j256.ormlite.table.DatabaseTableConfig;
import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.db.data.models.persisted.fields.BaseDBModelFields;
import com.quizlet.db.data.models.persisted.fields.DBStudySettingFields;
import com.quizlet.db.data.models.persisted.fields.DBUserStudyableFields;
import java.util.ArrayList;
import java.util.List;

/* loaded from: classes2.dex */
public final class DBStudySetting$$Configuration {
    public static List<DatabaseFieldConfig> getFieldConfigs() {
        ArrayList arrayList = new ArrayList();
        DatabaseFieldConfig databaseFieldConfigE = AbstractC4178x.e("localId", "localGeneratedId", true, 2, arrayList);
        DatabaseFieldConfig databaseFieldConfigD = AbstractC4178x.d(databaseFieldConfigE, "timestamp", 2, arrayList, databaseFieldConfigE);
        databaseFieldConfigD.setFieldName("personId");
        databaseFieldConfigD.setColumnName("personId");
        databaseFieldConfigD.setUniqueCombo(true);
        databaseFieldConfigD.setMaxForeignAutoRefreshLevel(2);
        arrayList.add(databaseFieldConfigD);
        DatabaseFieldConfig databaseFieldConfig = new DatabaseFieldConfig();
        databaseFieldConfig.setFieldName(DBUserStudyableFields.Names.STUDYABLE_TYPE);
        databaseFieldConfig.setColumnName(DBStudySettingFields.Names.STUDYABLE_TYPE);
        databaseFieldConfig.setUniqueCombo(true);
        DatabaseFieldConfig databaseFieldConfigC = AbstractC4178x.c(databaseFieldConfig, 2, arrayList, databaseFieldConfig, DBUserStudyableFields.Names.STUDYABLE_ID);
        databaseFieldConfigC.setColumnName(DBStudySettingFields.Names.STUDYABLE_ID);
        databaseFieldConfigC.setUniqueCombo(true);
        databaseFieldConfigC.setMaxForeignAutoRefreshLevel(2);
        arrayList.add(databaseFieldConfigC);
        DatabaseFieldConfig databaseFieldConfig2 = new DatabaseFieldConfig();
        databaseFieldConfig2.setFieldName("settingType");
        databaseFieldConfig2.setColumnName(DBStudySettingFields.Names.SETTING_TYPE);
        databaseFieldConfig2.setUniqueCombo(true);
        DatabaseFieldConfig databaseFieldConfigC2 = AbstractC4178x.c(databaseFieldConfig2, 2, arrayList, databaseFieldConfig2, "settingValue");
        DatabaseFieldConfig databaseFieldConfigT = AbstractC4178x.t(databaseFieldConfigC2, 2, arrayList, databaseFieldConfigC2, DBStudySettingFields.Names.SETTING_VALUE);
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

    public static DatabaseTableConfig<DBStudySetting> getTableConfig() {
        DatabaseTableConfig<DBStudySetting> databaseTableConfigG = AbstractC4178x.g(DBStudySetting.class, DBStudySetting.TABLE_NAME);
        databaseTableConfigG.setFieldConfigs(getFieldConfigs());
        return databaseTableConfigG;
    }
}

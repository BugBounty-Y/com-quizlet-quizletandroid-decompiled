package com.quizlet.db.data.models.persisted;

import com.j256.ormlite.field.DatabaseFieldConfig;
import com.j256.ormlite.table.DatabaseTableConfig;
import com.onetrust.otpublishers.headless.Public.Keys.OTUXParamsKeys;
import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.db.data.models.persisted.fields.BaseDBModelFields;
import com.quizlet.db.data.models.persisted.fields.DBFolderFields;
import java.util.ArrayList;
import java.util.List;

/* loaded from: classes2.dex */
public final class DBFolder$$Configuration {
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
        DatabaseFieldConfig databaseFieldConfigC = AbstractC4178x.c(databaseFieldConfig2, 2, arrayList, databaseFieldConfig2, "timestamp");
        DatabaseFieldConfig databaseFieldConfigC2 = AbstractC4178x.c(databaseFieldConfigC, 2, arrayList, databaseFieldConfigC, "personId");
        DatabaseFieldConfig databaseFieldConfigT = AbstractC4178x.t(databaseFieldConfigC2, 2, arrayList, databaseFieldConfigC2, "personId");
        DatabaseFieldConfig databaseFieldConfigD = AbstractC4178x.d(databaseFieldConfigT, "isHidden", 2, arrayList, databaseFieldConfigT);
        AbstractC4178x.q(databaseFieldConfigD, "webUrl", "_webUrl", 2);
        DatabaseFieldConfig databaseFieldConfigF = AbstractC4178x.f(arrayList, databaseFieldConfigD, DBFolderFields.Names.IS_COURSE_POWERED, DBFolderFields.Names.IS_COURSE_POWERED, 2);
        AbstractC4178x.q(databaseFieldConfigF, "schoolCourseDescription", DBFolderFields.Names.SCHOOL_COURSE_DESCRIPTION, 2);
        DatabaseFieldConfig databaseFieldConfigF2 = AbstractC4178x.f(arrayList, databaseFieldConfigF, "numStudySets", DBFolderFields.Names.NUM_SETS, 2);
        AbstractC4178x.q(databaseFieldConfigF2, DBFolderFields.Names.QPF_GENERATION_METHOD, DBFolderFields.Names.QPF_GENERATION_METHOD, 2);
        DatabaseFieldConfig databaseFieldConfigF3 = AbstractC4178x.f(arrayList, databaseFieldConfigF2, "dirty", "dirty", 2);
        AbstractC4178x.q(databaseFieldConfigF3, "isDeleted", "isDeleted", 2);
        DatabaseFieldConfig databaseFieldConfigF4 = AbstractC4178x.f(arrayList, databaseFieldConfigF3, "lastModified", "lastModified", 2);
        AbstractC4178x.q(databaseFieldConfigF4, BaseDBModelFields.Names.CLIENT_TIMESTAMP, BaseDBModelFields.Names.CLIENT_TIMESTAMP, 2);
        arrayList.add(databaseFieldConfigF4);
        return arrayList;
    }

    public static DatabaseTableConfig<DBFolder> getTableConfig() {
        DatabaseTableConfig<DBFolder> databaseTableConfigG = AbstractC4178x.g(DBFolder.class, "folder");
        databaseTableConfigG.setFieldConfigs(getFieldConfigs());
        return databaseTableConfigG;
    }
}

package com.quizlet.db.data.models.persisted;

import com.j256.ormlite.field.DatabaseFieldConfig;
import com.j256.ormlite.table.DatabaseTableConfig;
import com.onetrust.otpublishers.headless.Public.Keys.OTUXParamsKeys;
import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.db.data.models.persisted.fields.BaseDBModelFields;
import com.quizlet.db.data.models.persisted.fields.DBStudySetFields;
import java.util.ArrayList;
import java.util.List;

/* loaded from: classes2.dex */
public final class DBStudySet$$Configuration {
    public static List<DatabaseFieldConfig> getFieldConfigs() {
        ArrayList arrayList = new ArrayList();
        DatabaseFieldConfig databaseFieldConfigE = AbstractC4178x.e("id", "id", true, 2, arrayList);
        AbstractC4178x.q(databaseFieldConfigE, "localId", "localGeneratedId", 2);
        DatabaseFieldConfig databaseFieldConfigF = AbstractC4178x.f(arrayList, databaseFieldConfigE, "timestamp", DBStudySetFields.Names.TIMESTAMP, 2);
        AbstractC4178x.q(databaseFieldConfigF, DBStudySetFields.Names.PUBLISHED_TIMESTAMP, DBStudySetFields.Names.PUBLISHED_TIMESTAMP, 2);
        DatabaseFieldConfig databaseFieldConfigF2 = AbstractC4178x.f(arrayList, databaseFieldConfigF, "creatorId", "creatorId", 2);
        AbstractC4178x.q(databaseFieldConfigF2, "wordLang", DBStudySetFields.Names.WORD_LANGUAGE, 2);
        DatabaseFieldConfig databaseFieldConfigF3 = AbstractC4178x.f(arrayList, databaseFieldConfigF2, "defLang", DBStudySetFields.Names.DEFINITION_LANGUAGE, 2);
        AbstractC4178x.q(databaseFieldConfigF3, "title", "title", 2);
        arrayList.add(databaseFieldConfigF3);
        DatabaseFieldConfig databaseFieldConfig = new DatabaseFieldConfig();
        databaseFieldConfig.setFieldName("passwordUse");
        databaseFieldConfig.setMaxForeignAutoRefreshLevel(2);
        arrayList.add(databaseFieldConfig);
        DatabaseFieldConfig databaseFieldConfig2 = new DatabaseFieldConfig();
        databaseFieldConfig2.setFieldName("passwordEdit");
        DatabaseFieldConfig databaseFieldConfigC = AbstractC4178x.c(databaseFieldConfig2, 2, arrayList, databaseFieldConfig2, DBStudySetFields.Names.ACCESS_TYPE);
        DatabaseFieldConfig databaseFieldConfigT = AbstractC4178x.t(databaseFieldConfigC, 2, arrayList, databaseFieldConfigC, DBStudySetFields.Names.ACCESS_TYPE);
        AbstractC4178x.q(databaseFieldConfigT, DBStudySetFields.Names.ACCESS_CODE_PREFIX, DBStudySetFields.Names.ACCESS_CODE_PREFIX, 2);
        arrayList.add(databaseFieldConfigT);
        DatabaseFieldConfig databaseFieldConfig3 = new DatabaseFieldConfig();
        databaseFieldConfig3.setFieldName(OTUXParamsKeys.OT_UX_DESCRIPTION);
        databaseFieldConfig3.setMaxForeignAutoRefreshLevel(2);
        arrayList.add(databaseFieldConfig3);
        DatabaseFieldConfig databaseFieldConfig4 = new DatabaseFieldConfig();
        databaseFieldConfig4.setFieldName("numTerms");
        DatabaseFieldConfig databaseFieldConfigT2 = AbstractC4178x.t(databaseFieldConfig4, 2, arrayList, databaseFieldConfig4, DBStudySetFields.Names.NUM_TERMS);
        DatabaseFieldConfig databaseFieldConfigD = AbstractC4178x.d(databaseFieldConfigT2, "hasImages", 2, arrayList, databaseFieldConfigT2);
        AbstractC4178x.q(databaseFieldConfigD, "dWebUrl", "_webUrl", 2);
        arrayList.add(databaseFieldConfigD);
        DatabaseFieldConfig databaseFieldConfig5 = new DatabaseFieldConfig();
        databaseFieldConfig5.setFieldName("parentId");
        databaseFieldConfig5.setMaxForeignAutoRefreshLevel(2);
        arrayList.add(databaseFieldConfig5);
        DatabaseFieldConfig databaseFieldConfig6 = new DatabaseFieldConfig();
        databaseFieldConfig6.setFieldName("creationSource");
        DatabaseFieldConfig databaseFieldConfigC2 = AbstractC4178x.c(databaseFieldConfig6, 2, arrayList, databaseFieldConfig6, "privacyLockStatus");
        DatabaseFieldConfig databaseFieldConfigC3 = AbstractC4178x.c(databaseFieldConfigC2, 2, arrayList, databaseFieldConfigC2, DBStudySetFields.Names.READY_TO_CREATE);
        DatabaseFieldConfig databaseFieldConfigT3 = AbstractC4178x.t(databaseFieldConfigC3, 2, arrayList, databaseFieldConfigC3, DBStudySetFields.Names.READY_TO_CREATE);
        AbstractC4178x.q(databaseFieldConfigT3, DBStudySetFields.Names.HAS_DIAGRAMS, DBStudySetFields.Names.HAS_DIAGRAMS, 2);
        DatabaseFieldConfig databaseFieldConfigF4 = AbstractC4178x.f(arrayList, databaseFieldConfigT3, DBStudySetFields.Names.PASSWORD, DBStudySetFields.Names.PASSWORD, 2);
        AbstractC4178x.q(databaseFieldConfigF4, "dThumbnailUrl", DBStudySetFields.Names.THUMBNAIL_URL, 2);
        DatabaseFieldConfig databaseFieldConfigF5 = AbstractC4178x.f(arrayList, databaseFieldConfigF4, DBStudySetFields.Names.MCQ_COUNT, DBStudySetFields.Names.MCQ_COUNT, 2);
        AbstractC4178x.q(databaseFieldConfigF5, "dirty", "dirty", 2);
        DatabaseFieldConfig databaseFieldConfigF6 = AbstractC4178x.f(arrayList, databaseFieldConfigF5, "isDeleted", "isDeleted", 2);
        AbstractC4178x.q(databaseFieldConfigF6, "lastModified", "lastModified", 2);
        arrayList.add(databaseFieldConfigF6);
        DatabaseFieldConfig databaseFieldConfig7 = new DatabaseFieldConfig();
        databaseFieldConfig7.setFieldName(BaseDBModelFields.Names.CLIENT_TIMESTAMP);
        databaseFieldConfig7.setColumnName(BaseDBModelFields.Names.CLIENT_TIMESTAMP);
        databaseFieldConfig7.setMaxForeignAutoRefreshLevel(2);
        arrayList.add(databaseFieldConfig7);
        return arrayList;
    }

    public static DatabaseTableConfig<DBStudySet> getTableConfig() {
        DatabaseTableConfig<DBStudySet> databaseTableConfigG = AbstractC4178x.g(DBStudySet.class, "set");
        databaseTableConfigG.setFieldConfigs(getFieldConfigs());
        return databaseTableConfigG;
    }
}

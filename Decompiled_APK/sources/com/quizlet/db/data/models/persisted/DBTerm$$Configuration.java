package com.quizlet.db.data.models.persisted;

import com.j256.ormlite.field.DatabaseFieldConfig;
import com.j256.ormlite.table.DatabaseTableConfig;
import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.db.data.models.persisted.fields.BaseDBModelFields;
import com.quizlet.db.data.models.persisted.fields.DBTermFields;
import java.util.ArrayList;
import java.util.List;

/* loaded from: classes2.dex */
public final class DBTerm$$Configuration {
    public static List<DatabaseFieldConfig> getFieldConfigs() {
        ArrayList arrayList = new ArrayList();
        DatabaseFieldConfig databaseFieldConfigE = AbstractC4178x.e("id", "id", true, 2, arrayList);
        AbstractC4178x.q(databaseFieldConfigE, "localId", "localGeneratedId", 2);
        DatabaseFieldConfig databaseFieldConfigF = AbstractC4178x.f(arrayList, databaseFieldConfigE, "word", "term", 2);
        DatabaseFieldConfig databaseFieldConfigD = AbstractC4178x.d(databaseFieldConfigF, "definition", 2, arrayList, databaseFieldConfigF);
        AbstractC4178x.q(databaseFieldConfigD, "_wordAudioUrl", DBTermFields.Names.WORD_AUDIO_URL, 2);
        DatabaseFieldConfig databaseFieldConfigF2 = AbstractC4178x.f(arrayList, databaseFieldConfigD, "_definitionAudioUrl", DBTermFields.Names.DEFINITION_AUDIO_URL, 2);
        AbstractC4178x.q(databaseFieldConfigF2, "setId", "setId", 2);
        arrayList.add(databaseFieldConfigF2);
        DatabaseFieldConfig databaseFieldConfig = new DatabaseFieldConfig();
        databaseFieldConfig.setFieldName("imageUrl");
        databaseFieldConfig.setMaxForeignAutoRefreshLevel(2);
        arrayList.add(databaseFieldConfig);
        DatabaseFieldConfig databaseFieldConfig2 = new DatabaseFieldConfig();
        databaseFieldConfig2.setFieldName(DBTermFields.Names.DEFINITION_IMAGE_ID);
        DatabaseFieldConfig databaseFieldConfigT = AbstractC4178x.t(databaseFieldConfig2, 2, arrayList, databaseFieldConfig2, DBTermFields.Names.DEFINITION_IMAGE_ID);
        AbstractC4178x.q(databaseFieldConfigT, "rank", DBTermFields.Names.RANK, 2);
        arrayList.add(databaseFieldConfigT);
        DatabaseFieldConfig databaseFieldConfig3 = new DatabaseFieldConfig();
        databaseFieldConfig3.setFieldName("_wordTtsUrl");
        databaseFieldConfig3.setMaxForeignAutoRefreshLevel(2);
        arrayList.add(databaseFieldConfig3);
        DatabaseFieldConfig databaseFieldConfig4 = new DatabaseFieldConfig();
        databaseFieldConfig4.setFieldName("_definitionTtsUrl");
        DatabaseFieldConfig databaseFieldConfigC = AbstractC4178x.c(databaseFieldConfig4, 2, arrayList, databaseFieldConfig4, "wordCustomAudioId");
        DatabaseFieldConfig databaseFieldConfigC2 = AbstractC4178x.c(databaseFieldConfigC, 2, arrayList, databaseFieldConfigC, "definitionCustomAudioId");
        DatabaseFieldConfig databaseFieldConfigC3 = AbstractC4178x.c(databaseFieldConfigC2, 2, arrayList, databaseFieldConfigC2, "_definitionRichText");
        DatabaseFieldConfig databaseFieldConfigT2 = AbstractC4178x.t(databaseFieldConfigC3, 2, arrayList, databaseFieldConfigC3, DBTermFields.Names.DEFINITION_RICH_TEXT);
        AbstractC4178x.q(databaseFieldConfigT2, "_wordRichText", DBTermFields.Names.WORD_RICH_TEXT, 2);
        DatabaseFieldConfig databaseFieldConfigF3 = AbstractC4178x.f(arrayList, databaseFieldConfigT2, "_definitionCustomDistractors", DBTermFields.Names.DEFINITION_CUSTOM_DISTRACTORS, 2);
        AbstractC4178x.q(databaseFieldConfigF3, "dirty", "dirty", 2);
        DatabaseFieldConfig databaseFieldConfigF4 = AbstractC4178x.f(arrayList, databaseFieldConfigF3, "isDeleted", "isDeleted", 2);
        AbstractC4178x.q(databaseFieldConfigF4, "lastModified", "lastModified", 2);
        arrayList.add(databaseFieldConfigF4);
        DatabaseFieldConfig databaseFieldConfig5 = new DatabaseFieldConfig();
        databaseFieldConfig5.setFieldName(BaseDBModelFields.Names.CLIENT_TIMESTAMP);
        databaseFieldConfig5.setColumnName(BaseDBModelFields.Names.CLIENT_TIMESTAMP);
        databaseFieldConfig5.setMaxForeignAutoRefreshLevel(2);
        arrayList.add(databaseFieldConfig5);
        return arrayList;
    }

    public static DatabaseTableConfig<DBTerm> getTableConfig() {
        DatabaseTableConfig<DBTerm> databaseTableConfigG = AbstractC4178x.g(DBTerm.class, "term");
        databaseTableConfigG.setFieldConfigs(getFieldConfigs());
        return databaseTableConfigG;
    }
}

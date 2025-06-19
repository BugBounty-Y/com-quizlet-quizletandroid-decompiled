package com.quizlet.db.data.models.persisted;

import com.j256.ormlite.field.DatabaseFieldConfig;
import com.j256.ormlite.table.DatabaseTableConfig;
import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.db.data.models.persisted.fields.BaseDBModelFields;
import com.quizlet.db.data.models.persisted.fields.DBQuestionAttributeFields;
import java.util.ArrayList;
import java.util.List;

/* loaded from: classes2.dex */
public final class DBQuestionAttribute$$Configuration {
    public static List<DatabaseFieldConfig> getFieldConfigs() {
        ArrayList arrayList = new ArrayList();
        DatabaseFieldConfig databaseFieldConfigE = AbstractC4178x.e("id", "id", true, 2, arrayList);
        AbstractC4178x.q(databaseFieldConfigE, "localId", "localGeneratedId", 2);
        DatabaseFieldConfig databaseFieldConfigF = AbstractC4178x.f(arrayList, databaseFieldConfigE, DBQuestionAttributeFields.Names.ANSWER_ID, DBQuestionAttributeFields.Names.ANSWER_ID, 2);
        AbstractC4178x.q(databaseFieldConfigF, "personId", "personId", 2);
        DatabaseFieldConfig databaseFieldConfigF2 = AbstractC4178x.f(arrayList, databaseFieldConfigF, DBQuestionAttributeFields.Names.QUESTION_SIDE, DBQuestionAttributeFields.Names.QUESTION_SIDE, 2);
        AbstractC4178x.q(databaseFieldConfigF2, "setId", "setId", 2);
        DatabaseFieldConfig databaseFieldConfigF3 = AbstractC4178x.f(arrayList, databaseFieldConfigF2, "termId", "termId", 2);
        AbstractC4178x.q(databaseFieldConfigF3, DBQuestionAttributeFields.Names.TERM_SIDE, DBQuestionAttributeFields.Names.TERM_SIDE, 2);
        DatabaseFieldConfig databaseFieldConfigF4 = AbstractC4178x.f(arrayList, databaseFieldConfigF3, "timestamp", "timestamp", 2);
        AbstractC4178x.q(databaseFieldConfigF4, "dirty", "dirty", 2);
        DatabaseFieldConfig databaseFieldConfigF5 = AbstractC4178x.f(arrayList, databaseFieldConfigF4, "isDeleted", "isDeleted", 2);
        AbstractC4178x.q(databaseFieldConfigF5, "lastModified", "lastModified", 2);
        arrayList.add(databaseFieldConfigF5);
        DatabaseFieldConfig databaseFieldConfig = new DatabaseFieldConfig();
        databaseFieldConfig.setFieldName(BaseDBModelFields.Names.CLIENT_TIMESTAMP);
        databaseFieldConfig.setColumnName(BaseDBModelFields.Names.CLIENT_TIMESTAMP);
        databaseFieldConfig.setMaxForeignAutoRefreshLevel(2);
        arrayList.add(databaseFieldConfig);
        return arrayList;
    }

    public static DatabaseTableConfig<DBQuestionAttribute> getTableConfig() {
        DatabaseTableConfig<DBQuestionAttribute> databaseTableConfigG = AbstractC4178x.g(DBQuestionAttribute.class, DBQuestionAttribute.TABLE_NAME);
        databaseTableConfigG.setFieldConfigs(getFieldConfigs());
        return databaseTableConfigG;
    }
}

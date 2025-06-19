package com.quizlet.db.data.models.legacy;

import com.j256.ormlite.field.DatabaseFieldConfig;
import com.j256.ormlite.table.DatabaseTableConfig;
import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.db.data.models.persisted.fields.BaseDBModelFields;
import java.util.ArrayList;
import java.util.List;

/* loaded from: classes2.dex */
public final class LegacyFeedItem$$Configuration {
    public static List<DatabaseFieldConfig> getFieldConfigs() {
        ArrayList arrayList = new ArrayList();
        DatabaseFieldConfig databaseFieldConfigE = AbstractC4178x.e("pk", "pk", true, 2, arrayList);
        DatabaseFieldConfig databaseFieldConfigD = AbstractC4178x.d(databaseFieldConfigE, "setIdsString", 2, arrayList, databaseFieldConfigE);
        DatabaseFieldConfig databaseFieldConfigD2 = AbstractC4178x.d(databaseFieldConfigD, "feedUrl", 2, arrayList, databaseFieldConfigD);
        DatabaseFieldConfig databaseFieldConfigD3 = AbstractC4178x.d(databaseFieldConfigD2, "timestamp", 2, arrayList, databaseFieldConfigD2);
        DatabaseFieldConfig databaseFieldConfigD4 = AbstractC4178x.d(databaseFieldConfigD3, "originFeed", 2, arrayList, databaseFieldConfigD3);
        DatabaseFieldConfig databaseFieldConfigD5 = AbstractC4178x.d(databaseFieldConfigD4, "hidden", 2, arrayList, databaseFieldConfigD4);
        DatabaseFieldConfig databaseFieldConfigD6 = AbstractC4178x.d(databaseFieldConfigD5, "dataId", 2, arrayList, databaseFieldConfigD5);
        DatabaseFieldConfig databaseFieldConfigD7 = AbstractC4178x.d(databaseFieldConfigD6, "dataClass", 2, arrayList, databaseFieldConfigD6);
        AbstractC4178x.q(databaseFieldConfigD7, "localId", "localGeneratedId", 2);
        DatabaseFieldConfig databaseFieldConfigF = AbstractC4178x.f(arrayList, databaseFieldConfigD7, "dirty", "dirty", 2);
        AbstractC4178x.q(databaseFieldConfigF, "isDeleted", "isDeleted", 2);
        DatabaseFieldConfig databaseFieldConfigF2 = AbstractC4178x.f(arrayList, databaseFieldConfigF, "lastModified", "lastModified", 2);
        AbstractC4178x.q(databaseFieldConfigF2, BaseDBModelFields.Names.CLIENT_TIMESTAMP, BaseDBModelFields.Names.CLIENT_TIMESTAMP, 2);
        arrayList.add(databaseFieldConfigF2);
        return arrayList;
    }

    public static DatabaseTableConfig<LegacyFeedItem> getTableConfig() {
        DatabaseTableConfig<LegacyFeedItem> databaseTableConfigG = AbstractC4178x.g(LegacyFeedItem.class, "feed_item");
        databaseTableConfigG.setFieldConfigs(getFieldConfigs());
        return databaseTableConfigG;
    }
}

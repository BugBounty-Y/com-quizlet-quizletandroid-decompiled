package com.quizlet.db.data.models.legacy;

import com.amazon.device.ads.DTBMetricsConfiguration;
import com.j256.ormlite.field.DatabaseFieldConfig;
import com.j256.ormlite.table.DatabaseTableConfig;
import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.db.data.models.persisted.fields.BaseDBModelFields;
import java.util.ArrayList;
import java.util.List;

/* loaded from: classes2.dex */
public final class LegacyFeedResponseWrapper$$Configuration {
    public static List<DatabaseFieldConfig> getFieldConfigs() {
        ArrayList arrayList = new ArrayList();
        DatabaseFieldConfig databaseFieldConfigE = AbstractC4178x.e(DTBMetricsConfiguration.APSMETRICS_URL, DTBMetricsConfiguration.APSMETRICS_URL, true, 2, arrayList);
        AbstractC4178x.q(databaseFieldConfigE, "localId", "localGeneratedId", 2);
        DatabaseFieldConfig databaseFieldConfigF = AbstractC4178x.f(arrayList, databaseFieldConfigE, "dirty", "dirty", 2);
        AbstractC4178x.q(databaseFieldConfigF, "isDeleted", "isDeleted", 2);
        DatabaseFieldConfig databaseFieldConfigF2 = AbstractC4178x.f(arrayList, databaseFieldConfigF, "lastModified", "lastModified", 2);
        AbstractC4178x.q(databaseFieldConfigF2, BaseDBModelFields.Names.CLIENT_TIMESTAMP, BaseDBModelFields.Names.CLIENT_TIMESTAMP, 2);
        arrayList.add(databaseFieldConfigF2);
        return arrayList;
    }

    public static DatabaseTableConfig<LegacyFeedResponseWrapper> getTableConfig() {
        DatabaseTableConfig<LegacyFeedResponseWrapper> databaseTableConfigG = AbstractC4178x.g(LegacyFeedResponseWrapper.class, "feed_response_wrapper");
        databaseTableConfigG.setFieldConfigs(getFieldConfigs());
        return databaseTableConfigG;
    }
}

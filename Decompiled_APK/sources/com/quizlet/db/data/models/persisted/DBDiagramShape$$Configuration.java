package com.quizlet.db.data.models.persisted;

import com.j256.ormlite.field.DatabaseFieldConfig;
import com.j256.ormlite.table.DatabaseTableConfig;
import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.db.data.models.persisted.fields.BaseDBModelFields;
import com.quizlet.db.data.models.persisted.fields.DBDiagramShapeFields;
import java.util.ArrayList;
import java.util.List;

/* loaded from: classes2.dex */
public final class DBDiagramShape$$Configuration {
    public static List<DatabaseFieldConfig> getFieldConfigs() {
        ArrayList arrayList = new ArrayList();
        DatabaseFieldConfig databaseFieldConfigE = AbstractC4178x.e("id", "id", true, 2, arrayList);
        AbstractC4178x.q(databaseFieldConfigE, "localId", "localGeneratedId", 2);
        DatabaseFieldConfig databaseFieldConfigF = AbstractC4178x.f(arrayList, databaseFieldConfigE, "termId", "termId", 2);
        AbstractC4178x.q(databaseFieldConfigF, "setId", "setId", 2);
        DatabaseFieldConfig databaseFieldConfigF2 = AbstractC4178x.f(arrayList, databaseFieldConfigF, DBDiagramShapeFields.Names.SHAPE, DBDiagramShapeFields.Names.SHAPE, 2);
        AbstractC4178x.q(databaseFieldConfigF2, "timestamp", "timestamp", 2);
        DatabaseFieldConfig databaseFieldConfigF3 = AbstractC4178x.f(arrayList, databaseFieldConfigF2, "dirty", "dirty", 2);
        AbstractC4178x.q(databaseFieldConfigF3, "isDeleted", "isDeleted", 2);
        DatabaseFieldConfig databaseFieldConfigF4 = AbstractC4178x.f(arrayList, databaseFieldConfigF3, "lastModified", "lastModified", 2);
        AbstractC4178x.q(databaseFieldConfigF4, BaseDBModelFields.Names.CLIENT_TIMESTAMP, BaseDBModelFields.Names.CLIENT_TIMESTAMP, 2);
        arrayList.add(databaseFieldConfigF4);
        return arrayList;
    }

    public static DatabaseTableConfig<DBDiagramShape> getTableConfig() {
        DatabaseTableConfig<DBDiagramShape> databaseTableConfigG = AbstractC4178x.g(DBDiagramShape.class, DBDiagramShape.TABLE_NAME);
        databaseTableConfigG.setFieldConfigs(getFieldConfigs());
        return databaseTableConfigG;
    }
}

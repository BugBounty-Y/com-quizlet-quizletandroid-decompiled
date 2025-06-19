package com.j256.ormlite.android;

import com.j256.ormlite.db.DatabaseType;
import com.j256.ormlite.field.DatabaseFieldConfig;
import com.j256.ormlite.support.ConnectionSource;
import com.j256.ormlite.table.DatabaseTableConfig;
import java.lang.reflect.Field;
import java.sql.SQLException;
import java.util.ArrayList;

/* loaded from: classes2.dex */
public class DatabaseTableConfigUtil {
    public static <T> DatabaseTableConfig<T> fromClass(ConnectionSource connectionSource, Class<T> cls) throws SQLException {
        DatabaseType databaseType = connectionSource.getDatabaseType();
        String strExtractTableName = DatabaseTableConfig.extractTableName(databaseType, cls);
        ArrayList arrayList = new ArrayList();
        for (Class<T> superclass = cls; superclass != null; superclass = superclass.getSuperclass()) {
            for (Field field : superclass.getDeclaredFields()) {
                DatabaseFieldConfig databaseFieldConfigFromField = DatabaseFieldConfig.fromField(databaseType, strExtractTableName, field);
                if (databaseFieldConfigFromField != null && databaseFieldConfigFromField.isPersisted()) {
                    arrayList.add(databaseFieldConfigFromField);
                }
            }
        }
        if (arrayList.size() == 0) {
            return null;
        }
        return new DatabaseTableConfig<>(cls, strExtractTableName, arrayList);
    }
}

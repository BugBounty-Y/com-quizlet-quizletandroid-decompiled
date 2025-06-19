package com.j256.ormlite.table;

import com.j256.ormlite.support.ConnectionSource;
import java.sql.SQLException;
import java.util.Iterator;

/* loaded from: classes2.dex */
public abstract class BaseSchemaUtils {
    public void dumpSchema() throws SQLException {
        ConnectionSource connectionSource = getConnectionSource();
        for (Class<?> cls : getClasses()) {
            Iterator<String> it2 = TableUtils.getCreateTableStatements(connectionSource, cls).iterator();
            while (it2.hasNext()) {
                System.out.println(it2.next() + ";");
            }
        }
    }

    public abstract Class<?>[] getClasses();

    public abstract ConnectionSource getConnectionSource() throws SQLException;
}

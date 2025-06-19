package com.j256.ormlite.misc;

import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.compose.ui.node.B;
import java.io.Closeable;
import java.io.IOException;
import java.sql.SQLException;

/* loaded from: classes2.dex */
public class IOUtils {
    public static void closeQuietly(AutoCloseable autoCloseable) {
        if (autoCloseable != null) {
            try {
                B.t(autoCloseable);
            } catch (Exception unused) {
            }
        }
    }

    public static void closeThrowSqlException(AutoCloseable autoCloseable, String str) throws SQLException {
        if (autoCloseable != null) {
            try {
                B.t(autoCloseable);
            } catch (Exception e) {
                throw new SQLException(AbstractC0147y.d("could not close ", str), e);
            }
        }
    }

    public static void closeQuietly(Closeable closeable) throws IOException {
        if (closeable != null) {
            try {
                closeable.close();
            } catch (IOException unused) {
            }
        }
    }

    public static void closeThrowSqlException(Closeable closeable, String str) throws SQLException, IOException {
        if (closeable != null) {
            try {
                closeable.close();
            } catch (IOException e) {
                throw new SQLException(AbstractC0147y.d("could not close ", str), e);
            }
        }
    }
}

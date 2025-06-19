package com.google.android.gms.internal.mlkit_vision_camera;

import android.database.Cursor;
import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;
import java.util.TreeMap;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_camera.d2, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3331d2 {
    public static final /* synthetic */ int a = 0;

    public static String a(X509Certificate certificate) {
        Intrinsics.checkNotNullParameter(certificate, "certificate");
        if (certificate == null) {
            throw new IllegalArgumentException("Certificate pinning requires X509 certificates");
        }
        return "sha256/" + d(certificate).a();
    }

    public static final List b(Cursor cursor) {
        int columnIndex = cursor.getColumnIndex("id");
        int columnIndex2 = cursor.getColumnIndex("seq");
        int columnIndex3 = cursor.getColumnIndex("from");
        int columnIndex4 = cursor.getColumnIndex("to");
        kotlin.collections.builders.d dVar = new kotlin.collections.builders.d(0, 1, null);
        while (cursor.moveToNext()) {
            int i = cursor.getInt(columnIndex);
            int i2 = cursor.getInt(columnIndex2);
            String string = cursor.getString(columnIndex3);
            Intrinsics.checkNotNullExpressionValue(string, "cursor.getString(fromColumnIndex)");
            String string2 = cursor.getString(columnIndex4);
            Intrinsics.checkNotNullExpressionValue(string2, "cursor.getString(toColumnIndex)");
            dVar.add(new androidx.room.util.c(string, i, string2, i2));
        }
        return CollectionsKt.m0(kotlin.collections.A.a(dVar));
    }

    public static final androidx.room.util.d c(androidx.sqlite.db.framework.b bVar, String str, boolean z) throws IOException {
        Cursor cursorY = bVar.y("PRAGMA index_xinfo(`" + str + "`)");
        try {
            int columnIndex = cursorY.getColumnIndex("seqno");
            int columnIndex2 = cursorY.getColumnIndex("cid");
            int columnIndex3 = cursorY.getColumnIndex("name");
            int columnIndex4 = cursorY.getColumnIndex("desc");
            if (columnIndex != -1 && columnIndex2 != -1 && columnIndex3 != -1 && columnIndex4 != -1) {
                TreeMap treeMap = new TreeMap();
                TreeMap treeMap2 = new TreeMap();
                while (cursorY.moveToNext()) {
                    if (cursorY.getInt(columnIndex2) >= 0) {
                        int i = cursorY.getInt(columnIndex);
                        String columnName = cursorY.getString(columnIndex3);
                        String str2 = cursorY.getInt(columnIndex4) > 0 ? "DESC" : "ASC";
                        Integer numValueOf = Integer.valueOf(i);
                        Intrinsics.checkNotNullExpressionValue(columnName, "columnName");
                        treeMap.put(numValueOf, columnName);
                        treeMap2.put(Integer.valueOf(i), str2);
                    }
                }
                Collection collectionValues = treeMap.values();
                Intrinsics.checkNotNullExpressionValue(collectionValues, "columnsMap.values");
                List listW0 = CollectionsKt.w0(collectionValues);
                Collection collectionValues2 = treeMap2.values();
                Intrinsics.checkNotNullExpressionValue(collectionValues2, "ordersMap.values");
                androidx.room.util.d dVar = new androidx.room.util.d(str, z, listW0, CollectionsKt.w0(collectionValues2));
                cursorY.close();
                return dVar;
            }
            cursorY.close();
            return null;
        } finally {
        }
    }

    public static okio.k d(X509Certificate x509Certificate) {
        Intrinsics.checkNotNullParameter(x509Certificate, "<this>");
        okio.k kVar = okio.k.d;
        byte[] encoded = x509Certificate.getPublicKey().getEncoded();
        Intrinsics.checkNotNullExpressionValue(encoded, "publicKey.encoded");
        return com.quizlet.quizletandroid.ui.common.images.capture.b.l(-1234567890, encoded).c("SHA-256");
    }
}

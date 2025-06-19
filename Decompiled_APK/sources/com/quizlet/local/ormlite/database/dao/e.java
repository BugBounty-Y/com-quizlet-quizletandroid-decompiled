package com.quizlet.local.ormlite.database.dao;

import com.google.android.gms.internal.mlkit_vision_document_scanner.A;
import java.util.Collection;
import kotlin.text.x;

/* loaded from: classes3.dex */
public final class e {
    public static final e a = new e();

    public static String a(String str, Collection collection) {
        return x.c("\n                SELECT * FROM \"set\"\n                WHERE " + str + " IN " + A.b(collection) + "\n                AND isDeleted = 0\n        ");
    }
}

package com.google.android.gms.internal.mlkit_vision_document_scanner;

import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_document_scanner.y, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3763y {
    public static void a(Object obj, String str) {
        if (obj == null) {
            throw new IllegalArgumentException(str);
        }
    }

    public static String b(List folderIds, List groupIds, boolean z) {
        Intrinsics.checkNotNullParameter(folderIds, "folderIds");
        Intrinsics.checkNotNullParameter(groupIds, "groupIds");
        String strB = A.b(groupIds);
        String strB2 = A.b(folderIds);
        return kotlin.text.x.c("\n                UPDATE group_folder\n                SET isDeleted = " + (z ? 1 : 0) + "\n                WHERE groupId IN " + strB + "\n                AND folderId IN " + strB2 + ";\n\n                SELECT * FROM group_folder\n                WHERE isDeleted = " + (z ? 1 : 0) + "\n                AND groupId IN " + strB + "\n                AND folderId IN " + strB2 + ";\n            ");
    }
}

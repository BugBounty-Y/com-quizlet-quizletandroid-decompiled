package com.google.android.gms.internal.mlkit_vision_document_scanner;

import java.util.Collection;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class A {
    public static String a(boolean z) {
        Intrinsics.checkNotNullParameter("isDeleted", "isDeletedField");
        return z ? android.support.v4.media.session.a.k("isDeleted", " = 0") : "1";
    }

    public static final String b(Collection collection) {
        Intrinsics.checkNotNullParameter(collection, "<this>");
        return CollectionsKt.S(collection, ", ", "(", ")", null, 56);
    }
}

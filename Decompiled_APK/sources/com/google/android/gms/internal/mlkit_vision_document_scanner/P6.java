package com.google.android.gms.internal.mlkit_vision_document_scanner;

import com.quizlet.data.model.School;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class P6 {
    public static final /* synthetic */ int a = 0;

    public static final com.quizlet.edgy.ui.recyclerview.adapter.i a(School school) {
        Intrinsics.checkNotNullParameter(school, "<this>");
        long j = school.a;
        String str = school.b;
        String str2 = str == null ? "" : str;
        String str3 = school.j;
        return new com.quizlet.edgy.ui.recyclerview.adapter.i(j, school.i, str2, str3 == null ? "" : str3);
    }
}

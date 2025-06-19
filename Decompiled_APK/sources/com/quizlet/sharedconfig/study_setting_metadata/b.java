package com.quizlet.sharedconfig.study_setting_metadata;

import java.util.ArrayList;
import java.util.HashSet;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public enum b {
    WRITTEN(1),
    MATCHING(2),
    MULTIPLE_CHOICE(4),
    TRUE_FALSE(8),
    REVEAL_SELF_ASSESSMENT(16),
    MULTIPLE_CHOICE_WITH_NONE_OPTION(32),
    COPY_ANSWER(64),
    FILL_IN_THE_BLANK(1024);

    public final int a;

    b(int i) {
        this.a = i;
    }

    public static HashSet a(int i) {
        b[] bVarArrValues = values();
        a predicate = new a(i);
        Intrinsics.checkNotNullParameter(bVarArrValues, "<this>");
        Intrinsics.checkNotNullParameter(predicate, "predicate");
        ArrayList arrayList = new ArrayList();
        for (b bVar : bVarArrValues) {
            if (((Boolean) predicate.invoke(bVar)).booleanValue()) {
                arrayList.add(bVar);
            }
        }
        return new HashSet(arrayList);
    }
}

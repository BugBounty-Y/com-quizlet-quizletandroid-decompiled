package com.google.android.gms.internal.mlkit_vision_common;

import com.quizlet.quizletandroid.R;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class H3 {
    public static final int a(com.quizlet.generated.enums.I1 i1) {
        Intrinsics.checkNotNullParameter(i1, "<this>");
        int i = com.quizlet.features.subjects.model.e.a[i1.ordinal()];
        if (i == 1) {
            return R.string.explanation_subject_arts_and_humanities;
        }
        if (i == 2) {
            return R.string.explanation_subject_languages;
        }
        if (i == 3) {
            return R.string.explanation_subject_math;
        }
        if (i == 4) {
            return R.string.explanation_subject_science;
        }
        if (i == 5) {
            return R.string.explanation_subject_social_science;
        }
        throw new NoWhenBranchMatchedException();
    }

    public static boolean b(Object obj, Object obj2) {
        if (obj != obj2) {
            return obj != null && obj.equals(obj2);
        }
        return true;
    }
}

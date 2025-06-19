package com.quizlet.features.practicetest.common.data;

import com.quizlet.generated.enums.Q0;
import java.util.Set;
import kotlin.collections.C4933y;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public abstract class k {
    public static final Set a;

    static {
        Q0[] elements = {Q0.INACCURATE, Q0.IRRELEVANT, Q0.MISSING_INFO, Q0.OTHER_POOR_QUALITY, Q0.BAD_LANGUAGE, Q0.MATURE, Q0.HARASS_BULLY_OR_HATE};
        Intrinsics.checkNotNullParameter(elements, "elements");
        a = C4933y.T(elements);
    }
}

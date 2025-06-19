package com.quizlet.datafactory;

import com.quizlet.data.model.C4120d1;
import com.quizlet.data.model.C4124e1;
import com.quizlet.data.model.EnumC4130g1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class a {
    public static C4120d1 a(EnumC4130g1 progressType) {
        Intrinsics.checkNotNullParameter(progressType, "progressType");
        return new C4120d1(progressType);
    }

    public static C4124e1 b(C4120d1 c4120d1, String subtitle, String ctaButtonDeeplinkUrl, int i) {
        if ((i & 2) != 0) {
            c4120d1 = a(EnumC4130g1.a);
        }
        if ((i & 4) != 0) {
            subtitle = "12/46 cards flipped";
        }
        if ((i & 16) != 0) {
            ctaButtonDeeplinkUrl = "quizlet://quizlet.com/450606651/learn";
        }
        Intrinsics.checkNotNullParameter("Bio 1b (evolution) practice midterm", "title");
        Intrinsics.checkNotNullParameter(subtitle, "subtitle");
        Intrinsics.checkNotNullParameter("Continue", "ctaButtonText");
        Intrinsics.checkNotNullParameter(ctaButtonDeeplinkUrl, "ctaButtonDeeplinkUrl");
        return new C4124e1(c4120d1, subtitle, ctaButtonDeeplinkUrl);
    }
}

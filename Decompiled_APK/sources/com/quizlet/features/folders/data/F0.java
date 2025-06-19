package com.quizlet.features.folders.data;

import com.quizlet.quizletandroid.R;
import java.util.Comparator;

/* loaded from: classes3.dex */
public final class F0 extends K0 {
    public static final F0 b = new F0(4);
    public static final D0 c = new D0(R.string.sort_by_recent, R.drawable.ic_sys_caret_up, true, Integer.valueOf(R.string.sort_by_most_recent_first_a11y));
    public static final H0 d = new H0(G0.b, Integer.valueOf(R.drawable.ic_sys_arrow_up), true);
    public static final H0 e = new H0(I0.b, null, false);
    public static final com.google.zxing.aztec.encoder.c f = new com.google.zxing.aztec.encoder.c(12);

    @Override // com.quizlet.features.folders.data.K0
    public final D0 a() {
        return c;
    }

    @Override // com.quizlet.features.folders.data.K0
    public final Comparator b() {
        return f;
    }

    @Override // com.quizlet.features.folders.data.K0
    public final H0 c() {
        return d;
    }

    @Override // com.quizlet.features.folders.data.K0
    public final H0 d() {
        return e;
    }

    public final boolean equals(Object obj) {
        return this == obj || (obj instanceof F0);
    }

    public final int hashCode() {
        return -58185486;
    }

    public final String toString() {
        return "DateDesc";
    }
}

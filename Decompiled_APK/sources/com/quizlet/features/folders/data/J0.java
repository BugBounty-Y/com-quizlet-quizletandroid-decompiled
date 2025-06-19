package com.quizlet.features.folders.data;

import com.quizlet.quizletandroid.R;
import java.util.Comparator;

/* loaded from: classes3.dex */
public final class J0 extends K0 {
    public static final J0 b = new J0(2);
    public static final D0 c = new D0(R.string.sort_by_title, R.drawable.ic_sys_caret_up, true, Integer.valueOf(R.string.sort_by_title_z_to_a_a11y));
    public static final H0 d = new H0(E0.b, null, false);
    public static final H0 e = new H0(G0.b, Integer.valueOf(R.drawable.ic_sys_arrow_up), true);
    public static final com.google.zxing.aztec.encoder.c f = new com.google.zxing.aztec.encoder.c(14);

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
        return this == obj || (obj instanceof J0);
    }

    public final int hashCode() {
        return -10355377;
    }

    public final String toString() {
        return "NameDesc";
    }
}

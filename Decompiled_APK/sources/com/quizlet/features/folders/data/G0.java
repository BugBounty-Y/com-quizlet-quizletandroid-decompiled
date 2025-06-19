package com.quizlet.features.folders.data;

import com.quizlet.quizletandroid.R;
import java.util.Comparator;

/* loaded from: classes3.dex */
public final class G0 extends K0 {
    public static final G0 b = new G0(0);
    public static final D0 c = new D0(R.string.sort_by_recent, R.drawable.ic_sys_sort, false, null);
    public static final H0 d = new H0(E0.b, null, false);
    public static final H0 e = new H0(I0.b, null, false);

    @Override // com.quizlet.features.folders.data.K0
    public final D0 a() {
        return c;
    }

    @Override // com.quizlet.features.folders.data.K0
    public final Comparator b() {
        return null;
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
        return this == obj || (obj instanceof G0);
    }

    public final int hashCode() {
        return -593098162;
    }

    public final String toString() {
        return "Default";
    }
}

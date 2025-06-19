package com.google.firebase.perf.util;

import android.os.Bundle;

/* loaded from: classes2.dex */
public final class c {
    public static final com.google.firebase.perf.logging.a b = com.google.firebase.perf.logging.a.d();
    public final Bundle a;

    public c() {
        this(new Bundle());
    }

    public c(Bundle bundle) {
        this.a = (Bundle) bundle.clone();
    }
}

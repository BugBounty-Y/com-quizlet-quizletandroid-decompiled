package com.quizlet.humansecurity;

import android.content.Context;
import java.util.ArrayList;
import kotlin.collections.B;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class c {
    public static final ArrayList d = B.f("quizlet.com", "api.quizlet.com");
    public final Context a;
    public final com.google.firebase.perf.b b;
    public boolean c;

    public c(Context context, com.google.firebase.perf.b firebasePerformance) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(firebasePerformance, "firebasePerformance");
        this.a = context;
        this.b = firebasePerformance;
    }
}

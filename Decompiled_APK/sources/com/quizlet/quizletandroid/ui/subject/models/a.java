package com.quizlet.quizletandroid.ui.subject.models;

import io.reactivex.rxjava3.functions.i;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a implements i {
    public static final a a = new a();

    @Override // io.reactivex.rxjava3.functions.i
    public final boolean test(Object obj) {
        List it2 = (List) obj;
        Intrinsics.checkNotNullParameter(it2, "it");
        return !it2.isEmpty();
    }
}

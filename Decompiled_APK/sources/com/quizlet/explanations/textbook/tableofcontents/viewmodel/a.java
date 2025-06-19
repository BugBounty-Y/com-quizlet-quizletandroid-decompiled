package com.quizlet.explanations.textbook.tableofcontents.viewmodel;

import com.quizlet.data.model.k2;
import io.reactivex.rxjava3.functions.e;
import kotlin.jvm.internal.Intrinsics;
import kotlin.v;

/* loaded from: classes2.dex */
public final /* synthetic */ class a implements e {
    public static final a a = new a();

    @Override // io.reactivex.rxjava3.functions.e
    public final Object k(Object obj, Object obj2, Object obj3) {
        k2 p0 = (k2) obj;
        Boolean p1 = (Boolean) obj2;
        Boolean p2 = (Boolean) obj3;
        Intrinsics.checkNotNullParameter(p0, "p0");
        Intrinsics.checkNotNullParameter(p1, "p1");
        Intrinsics.checkNotNullParameter(p2, "p2");
        return new v(p0, p1, p2);
    }
}

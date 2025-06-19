package com.quizlet.quizletandroid.ui.setpage.terms.diagrams.data;

import com.quizlet.db.data.models.persisted.DBImageRef;
import io.reactivex.rxjava3.functions.h;
import io.reactivex.rxjava3.functions.i;
import java.util.List;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class b implements i, h {
    public static final b a = new b();
    public static final b b = new b();

    @Override // io.reactivex.rxjava3.functions.h
    public Object apply(Object obj) {
        List data = (List) obj;
        Intrinsics.checkNotNullParameter(data, "data");
        return (DBImageRef) CollectionsKt.L(data);
    }

    @Override // io.reactivex.rxjava3.functions.i
    public boolean test(Object obj) {
        List it2 = (List) obj;
        Intrinsics.checkNotNullParameter(it2, "it");
        return !it2.isEmpty();
    }
}

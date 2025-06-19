package com.quizlet.data.repository.classfolder;

import com.quizlet.data.model.D;
import io.reactivex.rxjava3.functions.h;
import java.util.ArrayList;
import java.util.List;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class d implements h, io.reactivex.rxjava3.functions.b {
    public static final d a = new d();

    @Override // io.reactivex.rxjava3.functions.b
    public Object apply(Object t, Object u) {
        Intrinsics.checkNotNullExpressionValue(t, "t");
        Intrinsics.checkNotNullExpressionValue(u, "u");
        List list = (List) u;
        List list2 = (List) t;
        Intrinsics.d(list2);
        Intrinsics.d(list);
        return CollectionsKt.c0(list2, list);
    }

    @Override // io.reactivex.rxjava3.functions.h
    public Object apply(Object obj) {
        List list = (List) obj;
        ArrayList arrayListM = assistantMode.refactored.a.m("classFolders", list);
        for (Object obj2 : list) {
            if (!Intrinsics.b(((D) obj2).f, Boolean.TRUE)) {
                arrayListM.add(obj2);
            }
        }
        return arrayListM;
    }
}

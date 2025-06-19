package com.quizlet.qutils.rx;

import io.reactivex.rxjava3.core.g;
import io.reactivex.rxjava3.functions.h;
import io.reactivex.rxjava3.internal.operators.maybe.f;
import java.util.List;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a implements h {
    public static final a b = new a(0);
    public static final a c = new a(1);
    public final /* synthetic */ int a;

    public /* synthetic */ a(int i) {
        this.a = i;
    }

    @Override // io.reactivex.rxjava3.functions.h
    public final Object apply(Object obj) {
        switch (this.a) {
            case 0:
                List list = (List) obj;
                Intrinsics.checkNotNullParameter(list, "list");
                return list.isEmpty() ? f.a : g.c(CollectionsKt.L(list));
            default:
                Boolean it2 = (Boolean) obj;
                Intrinsics.checkNotNullParameter(it2, "it");
                return Boolean.valueOf(!it2.booleanValue());
        }
    }
}

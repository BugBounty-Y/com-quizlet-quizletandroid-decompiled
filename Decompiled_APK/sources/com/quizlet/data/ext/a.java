package com.quizlet.data.ext;

import io.reactivex.rxjava3.core.g;
import io.reactivex.rxjava3.functions.h;
import io.reactivex.rxjava3.internal.operators.maybe.f;
import java.util.List;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class a implements h {
    public static final a b = new a(0);
    public static final a c = new a(1);
    public static final a d = new a(2);
    public final /* synthetic */ int a;

    public /* synthetic */ a(int i) {
        this.a = i;
    }

    @Override // io.reactivex.rxjava3.functions.h
    public final Object apply(Object obj) {
        switch (this.a) {
            case 0:
                List it2 = (List) obj;
                Intrinsics.checkNotNullParameter(it2, "it");
                return CollectionsKt.L(it2);
            case 1:
                List list = (List) obj;
                Intrinsics.checkNotNullParameter(list, "list");
                Object objFirstOrNull = CollectionsKt.firstOrNull(list);
                return objFirstOrNull != null ? g.c(objFirstOrNull) : f.a;
            default:
                List it3 = (List) obj;
                Intrinsics.checkNotNullParameter(it3, "it");
                return CollectionsKt.j0(it3);
        }
    }
}

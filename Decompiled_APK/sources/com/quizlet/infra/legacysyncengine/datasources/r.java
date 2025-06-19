package com.quizlet.infra.legacysyncengine.datasources;

import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class r implements io.reactivex.rxjava3.functions.h, io.reactivex.rxjava3.functions.i, io.reactivex.rxjava3.functions.b {
    public static final r b = new r(0);
    public static final r c = new r(1);
    public static final r d = new r(2);
    public static final r e = new r(3);
    public final /* synthetic */ int a;

    public /* synthetic */ r(int i) {
        this.a = i;
    }

    @Override // io.reactivex.rxjava3.functions.b
    public Object apply(Object t1, Object t2) {
        Intrinsics.checkNotNullExpressionValue(t1, "t1");
        Intrinsics.checkNotNullExpressionValue(t2, "t2");
        return new com.quizlet.infra.legacysyncengine.net.request.c(com.facebook.appevents.codeless.i.g(((com.quizlet.infra.legacysyncengine.net.request.c) t1).a, ((com.quizlet.infra.legacysyncengine.net.request.c) t2).a));
    }

    @Override // io.reactivex.rxjava3.functions.i
    public boolean test(Object obj) {
        switch (this.a) {
            case 1:
                Boolean value = (Boolean) obj;
                Intrinsics.checkNotNullParameter(value, "value");
                return value.booleanValue();
            default:
                Boolean value2 = (Boolean) obj;
                Intrinsics.checkNotNullParameter(value2, "value");
                return value2.booleanValue();
        }
    }

    @Override // io.reactivex.rxjava3.functions.h
    public Object apply(Object obj) {
        switch (this.a) {
            case 0:
                List models = (List) obj;
                Intrinsics.checkNotNullParameter(models, "models");
                return Boolean.valueOf((models.isEmpty() || models.size() == 200) ? false : true);
            default:
                List models2 = (List) obj;
                Intrinsics.checkNotNullParameter(models2, "models");
                return Boolean.valueOf((models2.isEmpty() || models2.size() == 200) ? false : true);
        }
    }
}

package com.quizlet.featuregate.contracts.properties;

import io.reactivex.rxjava3.functions.h;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class d implements h {
    public static final d b = new d(0);
    public static final d c = new d(1);
    public final /* synthetic */ int a;

    public /* synthetic */ d(int i) {
        this.a = i;
    }

    @Override // io.reactivex.rxjava3.functions.h
    public final Object apply(Object obj) {
        switch (this.a) {
            case 0:
                Integer it2 = (Integer) obj;
                Intrinsics.checkNotNullParameter(it2, "it");
                return Boolean.valueOf(it2.intValue() == 2);
            default:
                Integer it3 = (Integer) obj;
                Intrinsics.checkNotNullParameter(it3, "it");
                return Boolean.valueOf(it3.intValue() == 1);
        }
    }
}

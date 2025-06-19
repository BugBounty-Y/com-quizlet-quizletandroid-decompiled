package com.quizlet.offline.managers;

import io.reactivex.rxjava3.core.p;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class e implements io.reactivex.rxjava3.functions.h, io.reactivex.rxjava3.functions.i {
    public static final e b = new e(0);
    public static final e c = new e(1);
    public static final e d = new e(2);
    public static final e e = new e(3);
    public static final e f = new e(4);
    public final /* synthetic */ int a;

    public /* synthetic */ e(int i) {
        this.a = i;
    }

    @Override // io.reactivex.rxjava3.functions.h
    public Object apply(Object obj) {
        switch (this.a) {
            case 0:
                com.quizlet.data.connectivity.b it2 = (com.quizlet.data.connectivity.b) obj;
                Intrinsics.checkNotNullParameter(it2, "it");
                return Boolean.valueOf(it2.a);
            case 1:
            default:
                com.quizlet.data.connectivity.b it3 = (com.quizlet.data.connectivity.b) obj;
                Intrinsics.checkNotNullParameter(it3, "it");
                return Boolean.valueOf(it3.a);
            case 2:
                Boolean isAvailable = (Boolean) obj;
                Intrinsics.checkNotNullParameter(isAvailable, "isAvailable");
                return isAvailable.booleanValue() ? p.f(j.a) : p.f(j.b);
            case 3:
                com.quizlet.data.connectivity.b it4 = (com.quizlet.data.connectivity.b) obj;
                Intrinsics.checkNotNullParameter(it4, "it");
                return Boolean.valueOf(it4.a);
        }
    }

    @Override // io.reactivex.rxjava3.functions.i
    public boolean test(Object obj) {
        Boolean isConnected = (Boolean) obj;
        Intrinsics.checkNotNullParameter(isConnected, "isConnected");
        return isConnected.booleanValue();
    }
}

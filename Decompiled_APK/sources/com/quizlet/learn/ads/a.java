package com.quizlet.learn.ads;

import java.util.Map;
import kotlin.Pair;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final /* synthetic */ class a implements io.reactivex.rxjava3.functions.b, io.reactivex.rxjava3.functions.e {
    public static final a a = new a();
    public static final a b = new a();

    @Override // io.reactivex.rxjava3.functions.b
    public Object apply(Object obj, Object obj2) {
        Map p0 = (Map) obj;
        Map p1 = (Map) obj2;
        Intrinsics.checkNotNullParameter(p0, "p0");
        Intrinsics.checkNotNullParameter(p1, "p1");
        return new Pair(p0, p1);
    }

    @Override // io.reactivex.rxjava3.functions.e
    public Object k(Object obj, Object obj2, Object obj3) {
        Boolean isFreeUser = (Boolean) obj;
        Boolean isUnderAge = (Boolean) obj2;
        Boolean isLoggedOut = (Boolean) obj3;
        Intrinsics.checkNotNullParameter(isFreeUser, "isFreeUser");
        Intrinsics.checkNotNullParameter(isUnderAge, "isUnderAge");
        Intrinsics.checkNotNullParameter(isLoggedOut, "isLoggedOut");
        return Boolean.valueOf((isFreeUser.booleanValue() && !isUnderAge.booleanValue()) || isLoggedOut.booleanValue());
    }
}

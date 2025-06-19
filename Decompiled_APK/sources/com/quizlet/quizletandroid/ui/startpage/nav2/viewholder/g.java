package com.quizlet.quizletandroid.ui.startpage.nav2.viewholder;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class g implements io.reactivex.rxjava3.functions.i {
    public static final g a = new g();

    @Override // io.reactivex.rxjava3.functions.i
    public boolean test(Object obj) {
        Integer it2 = (Integer) obj;
        Intrinsics.checkNotNullParameter(it2, "it");
        return it2.intValue() == 0;
    }
}

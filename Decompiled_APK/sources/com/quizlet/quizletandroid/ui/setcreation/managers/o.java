package com.quizlet.quizletandroid.ui.setcreation.managers;

import java.util.Map;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class o implements io.reactivex.rxjava3.functions.i {
    public static final o a = new o();

    @Override // io.reactivex.rxjava3.functions.i
    public final boolean test(Object obj) {
        com.quizlet.infra.legacysyncengine.net.request.c pagedRequestCompletionInfo = (com.quizlet.infra.legacysyncengine.net.request.c) obj;
        Intrinsics.checkNotNullParameter(pagedRequestCompletionInfo, "pagedRequestCompletionInfo");
        com.quizlet.infra.legacysyncengine.net.request.i iVarA = pagedRequestCompletionInfo.a();
        Map map = iVarA.b;
        if (map != null && map.size() > 0) {
            return true;
        }
        Map map2 = iVarA.c;
        return map2 != null && map2.size() > 0;
    }
}

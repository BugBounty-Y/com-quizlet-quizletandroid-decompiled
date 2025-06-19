package com.quizlet.remote.model.union.folderwithcreator;

import com.quizlet.quizletandroid.ui.common.ads.C4636c;
import com.quizlet.quizletandroid.ui.setcreation.managers.n;
import io.reactivex.rxjava3.core.p;
import io.reactivex.rxjava3.internal.operators.single.g;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class e {
    public final b a;
    public final n b;

    public e(b dataSource, n mapper) {
        Intrinsics.checkNotNullParameter(dataSource, "dataSource");
        Intrinsics.checkNotNullParameter(mapper, "mapper");
        this.a = dataSource;
        this.b = mapper;
    }

    public static g b(e eVar, p pVar) {
        g remotes = pVar.g(new d());
        Intrinsics.checkNotNullExpressionValue(remotes, "map(...)");
        n nVar = eVar.b;
        Intrinsics.checkNotNullParameter(remotes, "remotes");
        Intrinsics.checkNotNullParameter(remotes, "remotes");
        g gVarG = remotes.g(new C4636c(nVar, 4));
        Intrinsics.checkNotNullExpressionValue(gVarG, "map(...)");
        return gVarG;
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object a(long r7, kotlin.coroutines.jvm.internal.c r9) {
        /*
            Method dump skipped, instructions count: 220
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.remote.model.union.folderwithcreator.e.a(long, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }
}

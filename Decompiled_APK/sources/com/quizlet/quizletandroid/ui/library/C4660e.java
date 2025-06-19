package com.quizlet.quizletandroid.ui.library;

import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.quizletandroid.ui.library.e, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final /* synthetic */ class C4660e implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ kotlinx.collections.immutable.e b;
    public final /* synthetic */ androidx.compose.foundation.lazy.grid.A c;
    public final /* synthetic */ Function1 d;
    public final /* synthetic */ boolean e;
    public final /* synthetic */ Function1 f;

    public /* synthetic */ C4660e(kotlinx.collections.immutable.e eVar, androidx.compose.foundation.lazy.grid.A a, Function1 function1, boolean z, Function1 function12, int i) {
        this.a = i;
        this.b = eVar;
        this.c = a;
        this.d = function1;
        this.e = z;
        this.f = function12;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                androidx.compose.foundation.lazy.grid.i LazyVerticalGrid = (androidx.compose.foundation.lazy.grid.i) obj;
                Intrinsics.checkNotNullParameter(LazyVerticalGrid, "$this$LazyVerticalGrid");
                androidx.navigation.compose.x xVar = new androidx.navigation.compose.x(18);
                kotlinx.collections.immutable.e eVar = this.b;
                LazyVerticalGrid.p(eVar.size(), new androidx.compose.ui.viewinterop.b(19, xVar, eVar), null, new com.quizlet.features.practicetest.common.composables.j(eVar, 1), new androidx.compose.runtime.internal.d(true, 1229287273, new C4664i(eVar, xVar, this.c, this.d, this.e, this.f, 0)));
                break;
            default:
                androidx.compose.foundation.lazy.grid.i LazyVerticalGrid2 = (androidx.compose.foundation.lazy.grid.i) obj;
                Intrinsics.checkNotNullParameter(LazyVerticalGrid2, "$this$LazyVerticalGrid");
                androidx.navigation.compose.x xVar2 = new androidx.navigation.compose.x(19);
                kotlinx.collections.immutable.e eVar2 = this.b;
                LazyVerticalGrid2.p(eVar2.size(), new androidx.compose.ui.viewinterop.b(20, xVar2, eVar2), null, new com.quizlet.features.practicetest.common.composables.j(eVar2, 2), new androidx.compose.runtime.internal.d(true, 1229287273, new C4664i(eVar2, xVar2, this.c, this.d, this.e, this.f, 1)));
                break;
        }
        return Unit.a;
    }
}

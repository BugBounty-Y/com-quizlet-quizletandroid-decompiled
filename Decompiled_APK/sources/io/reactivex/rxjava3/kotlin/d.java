package io.reactivex.rxjava3.kotlin;

import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class d implements io.reactivex.rxjava3.functions.a {
    public final /* synthetic */ Function0 a;

    public d(Function0 function0) {
        this.a = function0;
    }

    @Override // io.reactivex.rxjava3.functions.a
    public final /* synthetic */ void run() {
        Intrinsics.checkNotNullExpressionValue(this.a.invoke(), "invoke(...)");
    }
}

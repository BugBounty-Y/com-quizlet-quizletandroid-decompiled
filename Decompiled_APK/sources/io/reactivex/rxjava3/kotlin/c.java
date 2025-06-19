package io.reactivex.rxjava3.kotlin;

import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.r;

/* loaded from: classes3.dex */
public final class c extends r implements Function1 {
    public static final c b = new c(1, 0);
    public static final c c = new c(1, 1);
    public final /* synthetic */ int a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ c(int i, int i2) {
        super(i);
        this.a = i2;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object it2) {
        switch (this.a) {
            case 0:
                Intrinsics.checkNotNullParameter((Throwable) it2, "it");
                break;
            default:
                Intrinsics.checkNotNullParameter(it2, "it");
                break;
        }
        return Unit.a;
    }
}

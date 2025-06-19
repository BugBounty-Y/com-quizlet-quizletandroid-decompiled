package androidx.compose.animation.core;

import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.compose.animation.core.t0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0268t0 extends kotlin.jvm.internal.r implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ kotlin.jvm.internal.r b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    /* JADX WARN: Multi-variable type inference failed */
    public C0268t0(int i, Function1 function1) {
        super(1);
        this.a = i;
        switch (i) {
            case 1:
                this.b = (kotlin.jvm.internal.r) function1;
                super(1);
                break;
            case 2:
                this.b = (kotlin.jvm.internal.r) function1;
                super(1);
                break;
            case 3:
                this.b = (kotlin.jvm.internal.r) function1;
                super(1);
                break;
            default:
                this.b = (kotlin.jvm.internal.r) function1;
                break;
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r0v2, types: [kotlin.jvm.functions.Function1, kotlin.jvm.internal.r] */
    /* JADX WARN: Type inference failed for: r0v5, types: [kotlin.jvm.functions.Function1, kotlin.jvm.internal.r] */
    /* JADX WARN: Type inference failed for: r0v6, types: [kotlin.jvm.functions.Function1, kotlin.jvm.internal.r] */
    /* JADX WARN: Type inference failed for: r0v9, types: [kotlin.jvm.functions.Function1, kotlin.jvm.internal.r] */
    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                return this.b.invoke(Long.valueOf(((Number) obj).longValue()));
            case 1:
                return this.b.invoke(Long.valueOf(((Number) obj).longValue() / 1000000));
            case 2:
                androidx.compose.runtime.snapshots.h hVar = (androidx.compose.runtime.snapshots.h) this.b.invoke((androidx.compose.runtime.snapshots.l) obj);
                synchronized (androidx.compose.runtime.snapshots.m.b) {
                    androidx.compose.runtime.snapshots.m.c = androidx.compose.runtime.snapshots.m.c.h(hVar.g());
                    Unit unit = Unit.a;
                }
                return hVar;
            default:
                app.cash.sqldelight.driver.android.j execute = (app.cash.sqldelight.driver.android.j) obj;
                Intrinsics.checkNotNullParameter(execute, "$this$execute");
                return execute.c(this.b);
        }
    }
}

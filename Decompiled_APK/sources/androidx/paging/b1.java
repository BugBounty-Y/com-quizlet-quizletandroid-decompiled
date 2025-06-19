package androidx.paging;

import java.util.concurrent.CancellationException;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class b1 extends CancellationException {
    public final androidx.appcompat.app.L a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b1(androidx.appcompat.app.L runner) {
        super("Cancelled isolated runner");
        Intrinsics.checkNotNullParameter(runner, "runner");
        this.a = runner;
    }
}

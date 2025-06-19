package androidx.compose.ui.scrollcapture;

import android.os.CancellationSignal;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.r;

/* loaded from: classes.dex */
public final class g extends r implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ CancellationSignal b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ g(CancellationSignal cancellationSignal, int i) {
        super(1);
        this.a = i;
        this.b = cancellationSignal;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                if (((Throwable) obj) != null) {
                    this.b.cancel();
                }
                break;
            case 1:
                this.b.cancel();
                break;
            default:
                this.b.cancel();
                break;
        }
        return Unit.a;
    }
}

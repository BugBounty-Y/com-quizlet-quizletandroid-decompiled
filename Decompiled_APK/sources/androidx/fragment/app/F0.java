package androidx.fragment.app;

import android.view.View;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final /* synthetic */ class F0 implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ C1147o b;
    public final /* synthetic */ H0 c;

    public /* synthetic */ F0(C1147o c1147o, H0 h0, int i) {
        this.a = i;
        this.b = c1147o;
        this.c = h0;
    }

    @Override // java.lang.Runnable
    public final void run() {
        switch (this.a) {
            case 0:
                C1147o this$0 = this.b;
                Intrinsics.checkNotNullParameter(this$0, "this$0");
                H0 operation = this.c;
                Intrinsics.checkNotNullParameter(operation, "$operation");
                if (this$0.b.contains(operation)) {
                    J0 j0 = operation.a;
                    View view = operation.c.mView;
                    Intrinsics.checkNotNullExpressionValue(view, "operation.fragment.mView");
                    j0.a(view, this$0.a);
                    break;
                }
                break;
            case 1:
                C1147o this$02 = this.b;
                Intrinsics.checkNotNullParameter(this$02, "this$0");
                H0 operation2 = this.c;
                Intrinsics.checkNotNullParameter(operation2, "$operation");
                this$02.a(operation2);
                break;
            default:
                C1147o this$03 = this.b;
                Intrinsics.checkNotNullParameter(this$03, "this$0");
                H0 operation3 = this.c;
                Intrinsics.checkNotNullParameter(operation3, "$operation");
                this$03.b.remove(operation3);
                this$03.c.remove(operation3);
                break;
        }
    }
}

package androidx.fragment.app;

import android.view.View;
import android.view.ViewGroup;
import java.util.Iterator;
import java.util.Objects;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.fragment.app.k, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final /* synthetic */ class RunnableC1141k implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;
    public final /* synthetic */ C1145m c;

    public /* synthetic */ RunnableC1141k(C1145m c1145m, ViewGroup viewGroup) {
        this.a = 2;
        this.c = c1145m;
        this.b = viewGroup;
    }

    @Override // java.lang.Runnable
    public final void run() {
        switch (this.a) {
            case 0:
                H0 operation = (H0) this.b;
                Intrinsics.checkNotNullParameter(operation, "$operation");
                C1145m this$0 = this.c;
                Intrinsics.checkNotNullParameter(this$0, "this$0");
                if (AbstractC1136h0.N(2)) {
                    Objects.toString(operation);
                }
                operation.c(this$0);
                break;
            case 1:
                H0 operation2 = (H0) this.b;
                Intrinsics.checkNotNullParameter(operation2, "$operation");
                C1145m this$02 = this.c;
                Intrinsics.checkNotNullParameter(this$02, "this$0");
                if (AbstractC1136h0.N(2)) {
                    Objects.toString(operation2);
                }
                operation2.c(this$02);
                break;
            default:
                C1145m this$03 = this.c;
                Intrinsics.checkNotNullParameter(this$03, "this$0");
                ViewGroup container = (ViewGroup) this.b;
                Intrinsics.checkNotNullParameter(container, "$container");
                Iterator it2 = this$03.c.iterator();
                while (it2.hasNext()) {
                    H0 h0 = ((C1146n) it2.next()).a;
                    View view = h0.c.getView();
                    if (view != null) {
                        h0.a.a(view, container);
                    }
                }
                break;
        }
    }

    public /* synthetic */ RunnableC1141k(H0 h0, C1145m c1145m, int i) {
        this.a = i;
        this.b = h0;
        this.c = c1145m;
    }
}

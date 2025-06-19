package androidx.fragment.app;

import java.util.ArrayList;
import java.util.Iterator;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.fragment.app.u, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final /* synthetic */ class RunnableC1152u implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;

    public /* synthetic */ RunnableC1152u(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    @Override // java.lang.Runnable
    public final void run() {
        switch (this.a) {
            case 0:
                Fragment fragment = (Fragment) this.b;
                A0 a0 = fragment.mViewLifecycleOwner;
                a0.f.a(fragment.mSavedViewRegistryState);
                fragment.mSavedViewRegistryState = null;
                break;
            case 1:
                kotlin.jvm.internal.J seekCancelLambda = (kotlin.jvm.internal.J) this.b;
                Intrinsics.checkNotNullParameter(seekCancelLambda, "$seekCancelLambda");
                Function0 function0 = (Function0) seekCancelLambda.a;
                if (function0 != null) {
                    function0.invoke();
                    break;
                }
                break;
            case 2:
                ArrayList transitioningViews = (ArrayList) this.b;
                Intrinsics.checkNotNullParameter(transitioningViews, "$transitioningViews");
                s0.a(4, transitioningViews);
                break;
            case 3:
                C1145m this$0 = (C1145m) this.b;
                Intrinsics.checkNotNullParameter(this$0, "this$0");
                AbstractC1136h0.N(2);
                Iterator it2 = this$0.c.iterator();
                while (it2.hasNext()) {
                    ((C1146n) it2.next()).a.c(this$0);
                }
                break;
            default:
                Iterator it3 = ((AbstractC1136h0) this.b).o.iterator();
                while (it3.hasNext()) {
                    ((InterfaceC1128d0) it3.next()).getClass();
                }
                break;
        }
    }
}

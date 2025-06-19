package it.sephiroth.android.library.xtooltip;

import android.os.Handler;
import android.view.View;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.r;

/* loaded from: classes3.dex */
public final class c extends r implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ i b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ c(i iVar, int i) {
        super(2);
        this.a = i;
        this.b = iVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                Intrinsics.f((View.OnAttachStateChangeListener) obj2, "<anonymous parameter 1>");
                i iVar = this.b;
                Handler handler = iVar.i;
                h hVar = iVar.G;
                handler.removeCallbacks(hVar);
                handler.postDelayed(hVar, 0L);
                break;
            case 1:
                View view = (View) obj;
                View.OnAttachStateChangeListener listener = (View.OnAttachStateChangeListener) obj2;
                Intrinsics.f(listener, "listener");
                if (view != null) {
                    view.removeOnAttachStateChangeListener(listener);
                }
                i iVar2 = this.b;
                Handler handler2 = iVar2.i;
                handler2.removeCallbacks(iVar2.F);
                handler2.removeCallbacks(iVar2.G);
                break;
            default:
                View view2 = (View) obj;
                View.OnAttachStateChangeListener listener2 = (View.OnAttachStateChangeListener) obj2;
                Intrinsics.f(listener2, "listener");
                timber.log.c.a.g("anchorView detached from parent", new Object[0]);
                if (view2 != null) {
                    view2.removeOnAttachStateChangeListener(listener2);
                }
                this.b.a();
                break;
        }
        return Unit.a;
    }
}

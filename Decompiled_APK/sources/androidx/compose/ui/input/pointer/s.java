package androidx.compose.ui.input.pointer;

import android.view.MotionEvent;
import androidx.compose.animation.core.C0242g;
import androidx.compose.ui.node.g0;
import androidx.compose.ui.platform.C0971v;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;

/* loaded from: classes.dex */
public final class s extends kotlin.jvm.internal.r implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ androidx.compose.ui.viewinterop.p b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ s(androidx.compose.ui.viewinterop.p pVar, int i) {
        super(1);
        this.a = i;
        this.b = pVar;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        boolean zDispatchTouchEvent;
        switch (this.a) {
            case 0:
                MotionEvent motionEvent = (MotionEvent) obj;
                int actionMasked = motionEvent.getActionMasked();
                androidx.compose.ui.viewinterop.p pVar = this.b;
                switch (actionMasked) {
                    case 0:
                    case 1:
                    case 2:
                    case 3:
                    case 4:
                    case 5:
                    case 6:
                        zDispatchTouchEvent = pVar.dispatchTouchEvent(motionEvent);
                        break;
                    default:
                        zDispatchTouchEvent = pVar.dispatchGenericMotionEvent(motionEvent);
                        break;
                }
                return Boolean.valueOf(zDispatchTouchEvent);
            default:
                g0 g0Var = (g0) obj;
                C0971v c0971v = g0Var instanceof C0971v ? (C0971v) g0Var : null;
                androidx.compose.ui.viewinterop.p pVar2 = this.b;
                if (c0971v != null) {
                    C0242g c0242g = new C0242g(24, c0971v, pVar2);
                    androidx.compose.runtime.collection.b bVar = c0971v.A1;
                    if (!bVar.j(c0242g)) {
                        bVar.b(c0242g);
                    }
                }
                pVar2.removeAllViewsInLayout();
                return Unit.a;
        }
    }
}

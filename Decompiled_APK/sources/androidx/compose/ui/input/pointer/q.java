package androidx.compose.ui.input.pointer;

import android.view.MotionEvent;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class q extends kotlin.jvm.internal.r implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ r b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ q(r rVar, int i) {
        super(1);
        this.a = i;
        this.b = rVar;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                MotionEvent motionEvent = (MotionEvent) obj;
                Function1 function1 = this.b.b;
                if (function1 != null) {
                    function1.invoke(motionEvent);
                    return Unit.a;
                }
                Intrinsics.m("onTouchEvent");
                throw null;
            default:
                MotionEvent motionEvent2 = (MotionEvent) obj;
                Function1 function12 = this.b.b;
                if (function12 != null) {
                    function12.invoke(motionEvent2);
                    return Unit.a;
                }
                Intrinsics.m("onTouchEvent");
                throw null;
        }
    }
}

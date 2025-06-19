package androidx.compose.ui.window;

import android.os.Handler;
import android.os.Looper;
import androidx.compose.ui.platform.RunnableC0967t;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class j extends kotlin.jvm.internal.r implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ u b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ j(u uVar, int i) {
        super(1);
        this.a = i;
        this.b = uVar;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                androidx.compose.ui.layout.r rVarH = ((androidx.compose.ui.layout.r) obj).H();
                Intrinsics.d(rVarH);
                this.b.h(rVarH);
                break;
            case 1:
                androidx.compose.ui.unit.j jVar = new androidx.compose.ui.unit.j(((androidx.compose.ui.unit.j) obj).a);
                u uVar = this.b;
                uVar.m6setPopupContentSizefhxjrPA(jVar);
                uVar.i();
                break;
            default:
                Function0 function0 = (Function0) obj;
                u uVar2 = this.b;
                Handler handler = uVar2.getHandler();
                if ((handler != null ? handler.getLooper() : null) == Looper.myLooper()) {
                    function0.invoke();
                } else {
                    Handler handler2 = uVar2.getHandler();
                    if (handler2 != null) {
                        handler2.post(new RunnableC0967t(1, function0));
                    }
                }
                break;
        }
        return Unit.a;
    }
}

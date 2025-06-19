package androidx.constraintlayout.compose;

import android.os.Handler;
import android.os.Looper;
import androidx.compose.ui.platform.RunnableC0967t;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.r;

/* loaded from: classes.dex */
public final class h extends r implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ i b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ h(i iVar, int i) {
        super(1);
        this.a = i;
        this.b = iVar;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                Function0 function0 = (Function0) obj;
                if (Intrinsics.b(Looper.myLooper(), Looper.getMainLooper())) {
                    function0.invoke();
                } else {
                    i iVar = this.b;
                    Handler handler = iVar.b;
                    if (handler == null) {
                        handler = new Handler(Looper.getMainLooper());
                        iVar.b = handler;
                    }
                    handler.post(new RunnableC0967t(2, function0));
                }
                break;
            default:
                this.b.d = true;
                break;
        }
        return Unit.a;
    }
}

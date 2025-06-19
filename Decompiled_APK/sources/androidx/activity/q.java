package androidx.activity;

import android.os.Build;
import android.os.Handler;
import android.os.Looper;
import androidx.lifecycle.s0;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class q extends kotlin.jvm.internal.r implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ s b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ q(s sVar, int i) {
        super(0);
        this.a = i;
        this.b = sVar;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                s sVar = this.b;
                return new s0(sVar.getApplication(), sVar, sVar.getIntent() != null ? sVar.getIntent().getExtras() : null);
            case 1:
                this.b.reportFullyDrawn();
                return Unit.a;
            case 2:
                s sVar2 = this.b;
                return new C(sVar2.reportFullyDrawnExecutor, new q(sVar2, 1));
            default:
                s sVar3 = this.b;
                L l = new L(new RunnableC0032d(sVar3, 1));
                if (Build.VERSION.SDK_INT >= 33) {
                    if (Intrinsics.b(Looper.myLooper(), Looper.getMainLooper())) {
                        sVar3.getLifecycle().a(new C0036h(0, l, sVar3));
                    } else {
                        new Handler(Looper.getMainLooper()).post(new r(0, sVar3, l));
                    }
                }
                return l;
        }
    }
}

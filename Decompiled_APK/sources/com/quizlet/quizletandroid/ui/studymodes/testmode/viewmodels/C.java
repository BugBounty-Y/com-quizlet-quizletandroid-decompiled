package com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels;

import androidx.lifecycle.p0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class C implements io.reactivex.rxjava3.functions.d {
    public final /* synthetic */ G a;
    public final /* synthetic */ int b;
    public final /* synthetic */ int c;

    public C(G g, int i, int i2) {
        this.a = g;
        this.b = i;
        this.c = i2;
    }

    @Override // io.reactivex.rxjava3.functions.d
    public final void accept(Object obj) {
        Boolean isMeteringKillSwitchEnabled = (Boolean) obj;
        Intrinsics.checkNotNullParameter(isMeteringKillSwitchEnabled, "isMeteringKillSwitchEnabled");
        boolean zBooleanValue = isMeteringKillSwitchEnabled.booleanValue();
        G g = this.a;
        g.getClass();
        kotlinx.coroutines.E.A(p0.j(g), null, null, new E(this.b, this.c, g, zBooleanValue, null), 3);
    }
}

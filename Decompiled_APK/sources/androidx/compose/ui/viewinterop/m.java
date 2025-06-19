package androidx.compose.ui.viewinterop;

import android.content.Context;
import android.view.KeyEvent;
import android.view.View;
import androidx.compose.runtime.C0810n;
import androidx.compose.ui.node.g0;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.r;

/* loaded from: classes.dex */
public final class m extends r implements Function0 {
    public final /* synthetic */ Context a;
    public final /* synthetic */ Function1 b;
    public final /* synthetic */ C0810n c;
    public final /* synthetic */ androidx.compose.runtime.saveable.i d;
    public final /* synthetic */ int e;
    public final /* synthetic */ View f;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public m(Context context, Function1 function1, C0810n c0810n, androidx.compose.runtime.saveable.i iVar, int i, View view) {
        super(0);
        this.a = context;
        this.b = function1;
        this.c = c0810n;
        this.d = iVar;
        this.e = i;
        this.f = view;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        KeyEvent.Callback callback = this.f;
        Intrinsics.e(callback, "null cannot be cast to non-null type androidx.compose.ui.node.Owner");
        g0 g0Var = (g0) callback;
        return new p(this.a, this.b, this.c, this.d, this.e, g0Var).getLayoutNode();
    }
}

package com.skydoves.balloon.compose;

import android.content.Context;
import androidx.compose.ui.layout.V;
import androidx.compose.ui.platform.ComposeView;
import androidx.compose.ui.unit.j;
import java.util.ArrayList;
import kotlin.jvm.functions.Function1;

/* loaded from: classes3.dex */
public final /* synthetic */ class d implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;

    public /* synthetic */ d(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                return BalloonKt.Balloon$lambda$24$lambda$23((ComposeView) this.b, (j) obj);
            case 1:
                return BalloonKt.Balloon$lambda$27$lambda$26$lambda$25((ComposeView) this.b, (Context) obj);
            default:
                return BalloonKt$BalloonLayout$1$1.measure_3p2s80s$lambda$4((ArrayList) this.b, (V) obj);
        }
    }
}

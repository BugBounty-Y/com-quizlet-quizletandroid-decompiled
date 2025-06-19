package com.skydoves.balloon.compose;

import androidx.compose.ui.platform.ComposeView;
import androidx.compose.ui.semantics.v;
import kotlin.jvm.functions.Function1;

/* loaded from: classes3.dex */
public final /* synthetic */ class f implements Function1 {
    public final /* synthetic */ int a;

    public /* synthetic */ f(int i) {
        this.a = i;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                return BalloonKt$Balloon$balloonComposeView$1$1$1.invoke$lambda$1$lambda$0((v) obj);
            case 1:
                return BalloonKt.Balloon$lambda$1$lambda$0((ComposeView) obj);
            default:
                return BalloonKt.Balloon$lambda$3$lambda$2((BalloonWindow) obj);
        }
    }
}

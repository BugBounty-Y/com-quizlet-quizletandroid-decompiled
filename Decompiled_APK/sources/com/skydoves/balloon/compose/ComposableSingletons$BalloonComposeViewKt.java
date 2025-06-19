package com.skydoves.balloon.compose;

import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class ComposableSingletons$BalloonComposeViewKt {

    @NotNull
    public static final ComposableSingletons$BalloonComposeViewKt INSTANCE = new ComposableSingletons$BalloonComposeViewKt();

    /* renamed from: lambda-1, reason: not valid java name */
    @NotNull
    private static kotlin.jvm.functions.c f0lambda1 = new androidx.compose.runtime.internal.d(false, -1734990613, new kotlin.jvm.functions.c() { // from class: com.skydoves.balloon.compose.ComposableSingletons$BalloonComposeViewKt$lambda-1$1
        @Override // kotlin.jvm.functions.c
        public /* bridge */ /* synthetic */ Object invoke(Object obj, Object obj2, Object obj3) {
            invoke((BalloonComposeView) obj, (InterfaceC0806l) obj2, ((Number) obj3).intValue());
            return Unit.a;
        }

        public final void invoke(BalloonComposeView it2, InterfaceC0806l interfaceC0806l, int i) {
            Intrinsics.checkNotNullParameter(it2, "it");
            if ((i & 17) == 16) {
                C0814p c0814p = (C0814p) interfaceC0806l;
                if (c0814p.x()) {
                    c0814p.Q();
                }
            }
        }
    });

    @NotNull
    /* renamed from: getLambda-1$balloon_compose_release, reason: not valid java name */
    public final kotlin.jvm.functions.c m149getLambda1$balloon_compose_release() {
        return f0lambda1;
    }
}

package com.skydoves.balloon.compose;

import android.content.Context;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.platform.AndroidCompositionLocals_androidKt;
import com.skydoves.balloon.Balloon;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class RememberBalloonBuilderKt {
    @BalloonDsl
    @NotNull
    public static final Balloon.Builder rememberBalloonBuilder(Object obj, Context context, @NotNull Function1<? super Balloon.Builder, Unit> block, InterfaceC0806l interfaceC0806l, int i, int i2) {
        Intrinsics.checkNotNullParameter(block, "block");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.X(1887512655);
        if ((i2 & 1) != 0) {
            obj = null;
        }
        if ((i2 & 2) != 0) {
            context = (Context) c0814p.j(AndroidCompositionLocals_androidKt.b);
        }
        c0814p.X(-1325085354);
        boolean zF = c0814p.f(obj);
        Object objI = c0814p.I();
        if (zF || objI == C0804k.a) {
            objI = new Balloon.Builder(context);
            block.invoke(objI);
            c0814p.i0(objI);
        }
        Balloon.Builder builder = (Balloon.Builder) objI;
        c0814p.p(false);
        c0814p.p(false);
        return builder;
    }

    @BalloonDsl
    @NotNull
    public static final InterfaceC0773a0 rememberBalloonWindow(BalloonWindow balloonWindow, Object obj, InterfaceC0806l interfaceC0806l, int i, int i2) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.X(-1806639781);
        if ((i2 & 2) != 0) {
            obj = null;
        }
        c0814p.X(-1528537149);
        boolean zF = c0814p.f(obj);
        Object objI = c0814p.I();
        if (zF || objI == C0804k.a) {
            objI = C0776c.z(balloonWindow);
            c0814p.i0(objI);
        }
        InterfaceC0773a0 interfaceC0773a0 = (InterfaceC0773a0) objI;
        c0814p.p(false);
        c0814p.p(false);
        return interfaceC0773a0;
    }
}

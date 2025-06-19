package com.skydoves.balloon.compose;

import android.content.Context;
import android.view.ViewGroup;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0409s;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.G;
import androidx.compose.runtime.H;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.runtime.W0;
import androidx.compose.ui.layout.AbstractC0897s;
import androidx.compose.ui.layout.K;
import androidx.compose.ui.layout.r;
import androidx.compose.ui.n;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import androidx.compose.ui.platform.ComposeView;
import androidx.compose.ui.q;
import androidx.compose.ui.unit.j;
import androidx.lifecycle.p0;
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.mlkit_vision_barcode.R5;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3347h2;
import com.skydoves.balloon.Balloon;
import com.skydoves.balloon.compose.BalloonKt;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes3.dex */
public final class BalloonKt {

    @Metadata
    /* renamed from: com.skydoves.balloon.compose.BalloonKt$Balloon$6, reason: invalid class name */
    public static final class AnonymousClass6 implements Function2<InterfaceC0806l, Integer, Unit> {
        final /* synthetic */ BalloonComposeView $balloonComposeView;
        final /* synthetic */ Function2<InterfaceC0806l, Integer, Unit> $balloonContent;
        final /* synthetic */ Balloon.Builder $builder;
        final /* synthetic */ androidx.compose.ui.unit.b $density;
        final /* synthetic */ float $paddingEnd;
        final /* synthetic */ float $paddingStart;
        final /* synthetic */ int $screenWidth;

        /* JADX WARN: Multi-variable type inference failed */
        public AnonymousClass6(float f, float f2, Balloon.Builder builder, androidx.compose.ui.unit.b bVar, BalloonComposeView balloonComposeView, int i, Function2<? super InterfaceC0806l, ? super Integer, Unit> function2) {
            this.$paddingStart = f;
            this.$paddingEnd = f2;
            this.$builder = builder;
            this.$density = bVar;
            this.$balloonComposeView = balloonComposeView;
            this.$screenWidth = i;
            this.$balloonContent = function2;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public static final Unit invoke$lambda$3$lambda$2(int i, Balloon.Builder builder, androidx.compose.ui.unit.b bVar, BalloonComposeView balloonComposeView, r coordinates) {
            Intrinsics.checkNotNullParameter(coordinates, "coordinates");
            long jT = coordinates.t();
            float f = i;
            if (builder.getWidthRatio() * f == DefinitionKt.NO_Float_VALUE) {
                int i2 = (int) (jT >> 32);
                if (i2 <= i) {
                    i = i2;
                }
            } else {
                i = (int) (((builder.getWidthRatio() * f) - bVar.c0(builder.getMarginRight())) - bVar.c0(builder.getMarginLeft()));
            }
            long jA = R5.a(i, (int) (coordinates.t() & 4294967295L));
            balloonComposeView.m148updateSizeOfBalloonCardozmzZPI$balloon_compose_release(jA);
            balloonComposeView.getBalloonLayoutInfo$balloon_compose_release().setValue(new BalloonLayoutInfo(androidx.compose.ui.geometry.b.d(coordinates.d(0L)), androidx.compose.ui.geometry.b.e(coordinates.d(0L)), (int) (jA >> 32), (int) (jA & 4294967295L)));
            return Unit.a;
        }

        @Override // kotlin.jvm.functions.Function2
        public /* bridge */ /* synthetic */ Object invoke(Object obj, Object obj2) {
            invoke((InterfaceC0806l) obj, ((Number) obj2).intValue());
            return Unit.a;
        }

        public final void invoke(InterfaceC0806l interfaceC0806l, int i) {
            if ((i & 3) == 2) {
                C0814p c0814p = (C0814p) interfaceC0806l;
                if (c0814p.x()) {
                    c0814p.Q();
                    return;
                }
            }
            q qVarY = AbstractC0382e.y(androidx.compose.ui.draw.g.a(n.b, DefinitionKt.NO_Float_VALUE), this.$paddingStart, DefinitionKt.NO_Float_VALUE, this.$paddingEnd, DefinitionKt.NO_Float_VALUE, 10);
            C0814p c0814p2 = (C0814p) interfaceC0806l;
            c0814p2.X(1353898765);
            boolean zH = c0814p2.h(this.$builder) | c0814p2.f(this.$density) | c0814p2.f(this.$balloonComposeView);
            final int i2 = this.$screenWidth;
            final Balloon.Builder builder = this.$builder;
            final androidx.compose.ui.unit.b bVar = this.$density;
            final BalloonComposeView balloonComposeView = this.$balloonComposeView;
            Object objI = c0814p2.I();
            if (zH || objI == C0804k.a) {
                objI = new Function1() { // from class: com.skydoves.balloon.compose.e
                    @Override // kotlin.jvm.functions.Function1
                    public final Object invoke(Object obj) {
                        Balloon.Builder builder2 = builder;
                        androidx.compose.ui.unit.b bVar2 = bVar;
                        return BalloonKt.AnonymousClass6.invoke$lambda$3$lambda$2(i2, builder2, bVar2, balloonComposeView, (r) obj);
                    }
                };
                c0814p2.i0(objI);
            }
            c0814p2.p(false);
            q qVarL = AbstractC0897s.l(qVarY, (Function1) objI);
            Function2<InterfaceC0806l, Integer, Unit> function2 = this.$balloonContent;
            K kE = AbstractC0409s.e(androidx.compose.ui.b.a, false);
            int i3 = c0814p2.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p2.l();
            q qVarC = androidx.compose.ui.a.c(c0814p2, qVarL);
            InterfaceC0915k.D0.getClass();
            C0913i c0913i = C0914j.b;
            c0814p2.b0();
            if (c0814p2.O) {
                c0814p2.k(c0913i);
            } else {
                c0814p2.l0();
            }
            C0776c.E(c0814p2, kE, C0914j.f);
            C0776c.E(c0814p2, interfaceC0803j0L, C0914j.e);
            C0912h c0912h = C0914j.g;
            if (c0814p2.O || !Intrinsics.b(c0814p2.I(), Integer.valueOf(i3))) {
                android.support.v4.media.session.a.z(i3, c0814p2, i3, c0912h);
            }
            C0776c.E(c0814p2, qVarC, C0914j.d);
            c0814p2.X(1966243569);
            if (function2 != null) {
                function2.invoke(c0814p2, 0);
            }
            c0814p2.p(false);
            c0814p2.p(true);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:101:0x013d  */
    /* JADX WARN: Removed duplicated region for block: B:103:0x0141  */
    /* JADX WARN: Removed duplicated region for block: B:104:0x0143  */
    /* JADX WARN: Removed duplicated region for block: B:107:0x0160  */
    /* JADX WARN: Removed duplicated region for block: B:110:0x0198  */
    /* JADX WARN: Removed duplicated region for block: B:112:0x019c  */
    /* JADX WARN: Removed duplicated region for block: B:115:0x01ac  */
    /* JADX WARN: Removed duplicated region for block: B:119:0x01e7  */
    /* JADX WARN: Removed duplicated region for block: B:121:0x01f1  */
    /* JADX WARN: Removed duplicated region for block: B:125:0x0221  */
    /* JADX WARN: Removed duplicated region for block: B:138:0x029f  */
    /* JADX WARN: Removed duplicated region for block: B:185:0x049d  */
    /* JADX WARN: Removed duplicated region for block: B:188:? A[RETURN, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:36:0x006e  */
    /* JADX WARN: Removed duplicated region for block: B:38:0x0073  */
    /* JADX WARN: Removed duplicated region for block: B:47:0x0089  */
    /* JADX WARN: Removed duplicated region for block: B:49:0x008e  */
    /* JADX WARN: Removed duplicated region for block: B:58:0x00a6  */
    /* JADX WARN: Removed duplicated region for block: B:60:0x00aa  */
    /* JADX WARN: Removed duplicated region for block: B:69:0x00c2  */
    /* JADX WARN: Removed duplicated region for block: B:70:0x00c5  */
    /* JADX WARN: Removed duplicated region for block: B:79:0x00e2  */
    /* JADX WARN: Removed duplicated region for block: B:83:0x00f4  */
    /* JADX WARN: Removed duplicated region for block: B:85:0x00f8  */
    /* JADX WARN: Removed duplicated region for block: B:88:0x00fc  */
    /* JADX WARN: Removed duplicated region for block: B:91:0x0102  */
    /* JADX WARN: Removed duplicated region for block: B:95:0x011d  */
    /* JADX WARN: Removed duplicated region for block: B:97:0x0120  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void Balloon(androidx.compose.ui.q r25, @org.jetbrains.annotations.NotNull final com.skydoves.balloon.Balloon.Builder r26, java.lang.Object r27, kotlin.jvm.functions.Function1<? super androidx.compose.ui.platform.ComposeView, kotlin.Unit> r28, kotlin.jvm.functions.Function1<? super com.skydoves.balloon.compose.BalloonWindow, kotlin.Unit> r29, kotlin.jvm.functions.Function2<? super androidx.compose.runtime.InterfaceC0806l, ? super java.lang.Integer, kotlin.Unit> r30, @org.jetbrains.annotations.NotNull final kotlin.jvm.functions.c r31, androidx.compose.runtime.InterfaceC0806l r32, final int r33, final int r34) {
        /*
            Method dump skipped, instructions count: 1197
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.skydoves.balloon.compose.BalloonKt.Balloon(androidx.compose.ui.q, com.skydoves.balloon.Balloon$Builder, java.lang.Object, kotlin.jvm.functions.Function1, kotlin.jvm.functions.Function1, kotlin.jvm.functions.Function2, kotlin.jvm.functions.c, androidx.compose.runtime.l, int, int):void");
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final Unit Balloon$lambda$1$lambda$0(ComposeView it2) {
        Intrinsics.checkNotNullParameter(it2, "it");
        return Unit.a;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final Unit Balloon$lambda$14(q qVar, Balloon.Builder builder, Object obj, Function1 function1, Function1 function12, Function2 function2, kotlin.jvm.functions.c cVar, int i, int i2, InterfaceC0806l interfaceC0806l, int i3) {
        Balloon(qVar, builder, obj, function1, function12, function2, cVar, interfaceC0806l, C0776c.H(i | 1), i2);
        return Unit.a;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final Unit Balloon$lambda$24$lambda$23(ComposeView composeView, j jVar) {
        ViewGroup.LayoutParams layoutParams = composeView.getLayoutParams();
        if (layoutParams == null) {
            throw new NullPointerException("null cannot be cast to non-null type android.view.ViewGroup.LayoutParams");
        }
        long j = jVar.a;
        layoutParams.width = (int) (j >> 32);
        layoutParams.height = (int) (j & 4294967295L);
        composeView.setLayoutParams(layoutParams);
        return Unit.a;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final ComposeView Balloon$lambda$27$lambda$26$lambda$25(ComposeView composeView, Context it2) {
        Intrinsics.checkNotNullParameter(it2, "it");
        return composeView;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final Unit Balloon$lambda$3$lambda$2(BalloonWindow it2) {
        Intrinsics.checkNotNullParameter(it2, "it");
        return Unit.a;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final G Balloon$lambda$31$lambda$30(final BalloonComposeView balloonComposeView, final ComposeView composeView, H DisposableEffect) {
        Intrinsics.checkNotNullParameter(DisposableEffect, "$this$DisposableEffect");
        return new G() { // from class: com.skydoves.balloon.compose.BalloonKt$Balloon$lambda$31$lambda$30$$inlined$onDispose$1
            @Override // androidx.compose.runtime.G
            public void dispose() {
                balloonComposeView.dispose$balloon_compose_release();
                ComposeView composeView2 = composeView;
                AbstractC3347h2.e(composeView2, null);
                p0.n(composeView2, null);
                p0.o(composeView2, null);
            }
        };
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final Unit Balloon$lambda$32(q qVar, Balloon.Builder builder, Object obj, Function1 function1, Function1 function12, Function2 function2, kotlin.jvm.functions.c cVar, int i, int i2, InterfaceC0806l interfaceC0806l, int i3) {
        Balloon(qVar, builder, obj, function1, function12, function2, cVar, interfaceC0806l, C0776c.H(i | 1), i2);
        return Unit.a;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final Function2<InterfaceC0806l, Integer, Unit> Balloon$lambda$8(W0 w0) {
        return (Function2) w0.getValue();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final void BalloonLayout(q qVar, Function2<? super InterfaceC0806l, ? super Integer, Unit> function2, InterfaceC0806l interfaceC0806l, int i, int i2) {
        int i3;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1130020662);
        int i4 = i2 & 1;
        if (i4 != 0) {
            i3 = i | 6;
        } else if ((i & 6) == 0) {
            i3 = (c0814p.f(qVar) ? 4 : 2) | i;
        } else {
            i3 = i;
        }
        if ((i2 & 2) != 0) {
            i3 |= 48;
        } else if ((i & 48) == 0) {
            i3 |= c0814p.h(function2) ? 32 : 16;
        }
        if ((i3 & 19) == 18 && c0814p.x()) {
            c0814p.Q();
        } else {
            if (i4 != 0) {
                qVar = n.b;
            }
            c0814p.X(222699369);
            Object objI = c0814p.I();
            if (objI == C0804k.a) {
                objI = BalloonKt$BalloonLayout$1$1.INSTANCE;
                c0814p.i0(objI);
            }
            K k = (K) objI;
            c0814p.p(false);
            int i5 = ((i3 << 3) & ContentType.LONG_FORM_ON_DEMAND) | ((i3 >> 3) & 14) | 384;
            int i6 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            q qVarC = androidx.compose.ui.a.c(c0814p, qVar);
            InterfaceC0915k.D0.getClass();
            C0913i c0913i = C0914j.b;
            int i7 = ((i5 << 6) & 896) | 6;
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0776c.E(c0814p, k, C0914j.f);
            C0776c.E(c0814p, interfaceC0803j0L, C0914j.e);
            C0912h c0912h = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i6))) {
                android.support.v4.media.session.a.z(i6, c0814p, i6, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            function2.invoke(c0814p, Integer.valueOf((i7 >> 6) & 14));
            c0814p.p(true);
        }
        q qVar2 = qVar;
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.listitems.c(qVar2, function2, i, i2, 1);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final Unit BalloonLayout$lambda$34(q qVar, Function2 function2, int i, int i2, InterfaceC0806l interfaceC0806l, int i3) {
        BalloonLayout(qVar, function2, interfaceC0806l, C0776c.H(i | 1), i2);
        return Unit.a;
    }
}

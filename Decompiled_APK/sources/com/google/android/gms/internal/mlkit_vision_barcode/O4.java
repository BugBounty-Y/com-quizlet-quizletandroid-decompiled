package com.google.android.gms.internal.mlkit_vision_barcode;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.InterfaceC0806l;
import com.braze.C1483i;
import com.google.android.gms.internal.mlkit_vision_barcode.O4;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3578a5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3691o6;
import com.onetrust.otpublishers.headless.Public.OTUIDisplayReason.OTUIDisplayReasonCode;
import com.quizlet.assembly.compose.buttons.C4076a;
import com.quizlet.features.folders.data.EnumC4270a;
import com.quizlet.quizletandroid.R;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class O4 {
    public static final /* synthetic */ int a = 0;

    public static final long a(float f, float f2) {
        long jFloatToRawIntBits = (Float.floatToRawIntBits(f2) & 4294967295L) | (Float.floatToRawIntBits(f) << 32);
        int i = androidx.compose.ui.geometry.a.b;
        return jFloatToRawIntBits;
    }

    public static final void b(int i, InterfaceC0806l interfaceC0806l, androidx.compose.ui.q qVar, Function0 onClick) {
        Intrinsics.checkNotNullParameter(onClick, "onClick");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1292734282);
        int i2 = i | 6 | (c0814p.h(onClick) ? 32 : 16);
        if ((i2 & 19) == 18 && c0814p.x()) {
            c0814p.Q();
        } else {
            qVar = androidx.compose.ui.n.b;
            androidx.compose.ui.q qVarG = androidx.compose.ui.platform.N.G(qVar, "searchButton");
            com.quizlet.themes.e.a(c0814p).a.getClass();
            AbstractC3578a5.a(com.quizlet.ui.resources.icons.d.H(c0814p), AbstractC3106b5.d(c0814p, R.string.search), qVarG, onClick, false, C4076a.e, null, 0L, c0814p, (i2 << 6) & 7168, OTUIDisplayReasonCode.UIShownCode.PC_SHOWN_BACKWARD_COMPATIBILITY);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.features.flashcards.creatormarketing.b(qVar, onClick, i, 2);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:15:0x003c  */
    /* JADX WARN: Removed duplicated region for block: B:16:0x003f  */
    /* JADX WARN: Removed duplicated region for block: B:19:0x0048  */
    /* JADX WARN: Removed duplicated region for block: B:20:0x004b  */
    /* JADX WARN: Removed duplicated region for block: B:23:0x0056  */
    /* JADX WARN: Removed duplicated region for block: B:24:0x0059  */
    /* JADX WARN: Removed duplicated region for block: B:27:0x0064  */
    /* JADX WARN: Removed duplicated region for block: B:28:0x0067  */
    /* JADX WARN: Removed duplicated region for block: B:35:0x0086  */
    /* JADX WARN: Removed duplicated region for block: B:44:0x00a6  */
    /* JADX WARN: Removed duplicated region for block: B:46:0x00ac  */
    /* JADX WARN: Removed duplicated region for block: B:51:0x0108  */
    /* JADX WARN: Removed duplicated region for block: B:53:? A[RETURN, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void c(androidx.compose.ui.focus.h r22, androidx.compose.ui.n r23, boolean r24, int r25, kotlin.jvm.functions.Function1 r26, kotlin.jvm.functions.Function0 r27, kotlin.jvm.functions.Function0 r28, kotlin.jvm.functions.Function1 r29, androidx.compose.runtime.InterfaceC0806l r30, int r31, int r32) {
        /*
            Method dump skipped, instructions count: 285
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_barcode.O4.c(androidx.compose.ui.focus.h, androidx.compose.ui.n, boolean, int, kotlin.jvm.functions.Function1, kotlin.jvm.functions.Function0, kotlin.jvm.functions.Function0, kotlin.jvm.functions.Function1, androidx.compose.runtime.l, int, int):void");
    }

    public static final void d(final Function0 onBackClicked, final Function1 onFolderEvent, final com.quizlet.features.folders.menu.m menuState, final EnumC4270a copyFolderState, final boolean z, androidx.compose.ui.n nVar, final boolean z2, final boolean z3, InterfaceC0806l interfaceC0806l, final int i) {
        final androidx.compose.ui.n nVar2;
        Intrinsics.checkNotNullParameter(onBackClicked, "onBackClicked");
        Intrinsics.checkNotNullParameter(onFolderEvent, "onFolderEvent");
        Intrinsics.checkNotNullParameter(menuState, "menuState");
        Intrinsics.checkNotNullParameter(copyFolderState, "copyFolderState");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(166224738);
        int i2 = i | (c0814p.h(onBackClicked) ? 4 : 2) | (c0814p.h(onFolderEvent) ? 32 : 16) | (c0814p.f(menuState) ? 256 : 128) | (c0814p.f(copyFolderState) ? 2048 : 1024) | (c0814p.g(z) ? 16384 : 8192) | 196608 | (c0814p.g(z2) ? 1048576 : 524288) | (c0814p.g(z3) ? 8388608 : 4194304);
        if ((4793491 & i2) == 4793490 && c0814p.x()) {
            c0814p.Q();
            nVar2 = nVar;
        } else {
            androidx.compose.ui.n nVar3 = androidx.compose.ui.n.b;
            Object[] objArr = new Object[0];
            c0814p.X(1414377223);
            boolean z4 = (29360128 & i2) == 8388608;
            Object objI = c0814p.I();
            if (z4 || objI == C0804k.a) {
                objI = new C1483i(z3, 11);
                c0814p.i0(objI);
            }
            c0814p.p(false);
            InterfaceC0773a0 interfaceC0773a0 = (InterfaceC0773a0) L4.d(objArr, null, (Function0) objI, c0814p, 0, 6);
            long jG = ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).b.g();
            com.quizlet.themes.e.a(c0814p).a.getClass();
            AbstractC3691o6.c(nVar3, null, jG, 0L, com.quizlet.ui.resources.icons.d.m(c0814p), onBackClicked, androidx.compose.runtime.internal.e.e(1926680260, new com.quizlet.features.folders.composables.I(z, onFolderEvent, copyFolderState, interfaceC0773a0, z2, menuState), c0814p), null, c0814p, ((i2 << 15) & 458752) | 1572870, 138);
            nVar2 = nVar3;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new Function2(onFolderEvent, menuState, copyFolderState, z, nVar2, z2, z3, i) { // from class: com.quizlet.features.folders.composables.G
                public final /* synthetic */ Function1 b;
                public final /* synthetic */ com.quizlet.features.folders.menu.m c;
                public final /* synthetic */ EnumC4270a d;
                public final /* synthetic */ boolean e;
                public final /* synthetic */ androidx.compose.ui.n f;
                public final /* synthetic */ boolean g;
                public final /* synthetic */ boolean h;

                @Override // kotlin.jvm.functions.Function2
                public final Object invoke(Object obj, Object obj2) {
                    ((Integer) obj2).getClass();
                    int iH = C0776c.H(1);
                    boolean z5 = this.g;
                    boolean z6 = this.h;
                    O4.d(this.a, this.b, this.c, this.d, this.e, this.f, z5, z6, (InterfaceC0806l) obj, iH);
                    return Unit.a;
                }
            };
        }
    }
}

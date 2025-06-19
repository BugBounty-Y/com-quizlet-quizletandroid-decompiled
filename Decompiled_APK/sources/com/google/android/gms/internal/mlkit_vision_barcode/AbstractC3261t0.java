package com.google.android.gms.internal.mlkit_vision_barcode;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.graphics.vector.C0867f;
import androidx.compose.ui.q;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3261t0;
import com.google.android.gms.internal.mlkit_vision_barcode.D6;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3721s5;
import java.util.Set;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_barcode.t0, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3261t0 {
    public static C0867f a;

    public static final void a(final D6 front, final D6 back, final com.quizlet.features.infra.models.flashcards.h visibleSide, final Function0 onCardClick, final Function1 onCardSpeakButtonClick, final Function0 onCardStarredButtonClick, final Function1 onTextLongClick, final boolean z, final boolean z2, androidx.compose.ui.q qVar, int i, InterfaceC0806l interfaceC0806l, final int i2) {
        int i3;
        androidx.compose.ui.q qVar2;
        com.quizlet.assembly.compose.components.flashcards.a aVar;
        boolean z3;
        C0814p c0814p;
        final androidx.compose.ui.q qVar3;
        final int i4;
        Intrinsics.checkNotNullParameter(front, "front");
        Intrinsics.checkNotNullParameter(back, "back");
        Intrinsics.checkNotNullParameter(visibleSide, "visibleSide");
        Intrinsics.checkNotNullParameter(onCardClick, "onCardClick");
        Intrinsics.checkNotNullParameter(onCardSpeakButtonClick, "onCardSpeakButtonClick");
        Intrinsics.checkNotNullParameter(onCardStarredButtonClick, "onCardStarredButtonClick");
        Intrinsics.checkNotNullParameter(onTextLongClick, "onTextLongClick");
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(464345606);
        int i5 = i2 | (c0814p2.h(front) ? 4 : 2) | (c0814p2.h(back) ? 32 : 16) | (c0814p2.f(visibleSide) ? 256 : 128) | (c0814p2.h(onCardClick) ? 2048 : 1024) | (c0814p2.h(onCardSpeakButtonClick) ? 16384 : 8192) | (c0814p2.h(onCardStarredButtonClick) ? 131072 : 65536) | (c0814p2.h(onTextLongClick) ? 1048576 : 524288) | (c0814p2.g(z) ? 8388608 : 4194304) | (c0814p2.g(z2) ? 67108864 : 33554432) | 805306368;
        if ((306783379 & i5) == 306783378 && c0814p2.x()) {
            c0814p2.Q();
            qVar3 = qVar;
            i4 = i;
            c0814p = c0814p2;
        } else {
            c0814p2.S();
            if ((i2 & 1) == 0 || c0814p2.w()) {
                androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
                i3 = AbstractC3205m5.g(c0814p2).a;
                qVar2 = nVar;
            } else {
                c0814p2.Q();
                qVar2 = qVar;
                i3 = i;
            }
            c0814p2.q();
            int iOrdinal = visibleSide.ordinal();
            if (iOrdinal == 0) {
                aVar = com.quizlet.assembly.compose.components.flashcards.a.d;
            } else {
                if (iOrdinal != 1) {
                    throw new NoWhenBranchMatchedException();
                }
                aVar = com.quizlet.assembly.compose.components.flashcards.a.c;
            }
            c0814p2.X(1295654344);
            boolean z4 = (i5 & 896) == 256;
            Object objI = c0814p2.I();
            Object obj = C0804k.a;
            if (z4 || objI == obj) {
                objI = C0776c.z(aVar);
                c0814p2.i0(objI);
            }
            InterfaceC0773a0 interfaceC0773a0 = (InterfaceC0773a0) objI;
            Object objG = com.google.android.gms.measurement.internal.Z.g(1295657052, c0814p2, false);
            if (objG == obj) {
                Set set = androidx.compose.material3.windowsizeclass.c.b;
                objG = i3 == 0 ? com.quizlet.assembly.compose.components.flashcards.d.b : com.quizlet.assembly.compose.components.flashcards.d.a;
                c0814p2.i0(objG);
            }
            com.quizlet.assembly.compose.components.flashcards.d dVar = (com.quizlet.assembly.compose.components.flashcards.d) objG;
            c0814p2.p(false);
            androidx.compose.ui.q qVarG = androidx.compose.ui.platform.N.G(qVar2, "flashcards_card_view");
            com.quizlet.assembly.compose.components.flashcards.b bVar = (com.quizlet.assembly.compose.components.flashcards.b) interfaceC0773a0.getValue();
            c0814p2.X(1295705107);
            boolean zF = c0814p2.f(interfaceC0773a0) | ((i5 & 7168) == 2048);
            Object objI2 = c0814p2.I();
            if (zF || objI2 == obj) {
                z3 = false;
                objI2 = new com.quizlet.features.flashcards.views.composables.f(onCardClick, interfaceC0773a0, 0);
                c0814p2.i0(objI2);
            } else {
                z3 = false;
            }
            c0814p2.p(z3);
            c0814p = c0814p2;
            AbstractC3721s5.a(bVar, qVarG, dVar, null, 0L, null, null, (Function1) objI2, androidx.compose.runtime.internal.e.e(-971298120, new com.quizlet.features.flashcards.views.composables.j(back, z, z2, onCardSpeakButtonClick, onCardStarredButtonClick, onTextLongClick, interfaceC0773a0, onCardClick, 0), c0814p2), androidx.compose.runtime.internal.e.e(1167541753, new com.quizlet.features.flashcards.views.composables.j(front, z, z2, onCardSpeakButtonClick, onCardStarredButtonClick, onTextLongClick, interfaceC0773a0, onCardClick, 1), c0814p2), 0, c0814p, 905970048, 1144);
            qVar3 = qVar2;
            i4 = i3;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new Function2(back, visibleSide, onCardClick, onCardSpeakButtonClick, onCardStarredButtonClick, onTextLongClick, z, z2, qVar3, i4, i2) { // from class: com.quizlet.features.flashcards.views.composables.g
                public final /* synthetic */ D6 b;
                public final /* synthetic */ com.quizlet.features.infra.models.flashcards.h c;
                public final /* synthetic */ Function0 d;
                public final /* synthetic */ Function1 e;
                public final /* synthetic */ Function0 f;
                public final /* synthetic */ Function1 g;
                public final /* synthetic */ boolean h;
                public final /* synthetic */ boolean i;
                public final /* synthetic */ q j;
                public final /* synthetic */ int k;

                @Override // kotlin.jvm.functions.Function2
                public final Object invoke(Object obj2, Object obj3) {
                    ((Integer) obj3).getClass();
                    int iH = C0776c.H(1);
                    D6 d6 = this.a;
                    D6 d62 = this.b;
                    q qVar4 = this.j;
                    int i6 = this.k;
                    AbstractC3261t0.a(d6, d62, this.c, this.d, this.e, this.f, this.g, this.h, this.i, qVar4, i6, (InterfaceC0806l) obj2, iH);
                    return Unit.a;
                }
            };
        }
    }

    public static final void b(InterfaceC0773a0 interfaceC0773a0, Function0 function0) {
        interfaceC0773a0.setValue(((com.quizlet.assembly.compose.components.flashcards.b) interfaceC0773a0.getValue()).a());
        function0.invoke();
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:169:0x050b  */
    /* JADX WARN: Type inference failed for: r15v1 */
    /* JADX WARN: Type inference failed for: r15v6 */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void c(final java.lang.String r42, final com.quizlet.assembly.compose.modals.x r43, androidx.compose.ui.q r44, final java.lang.String r45, final com.quizlet.search.data.c r46, final androidx.compose.foundation.layout.z0 r47, final com.quizlet.search.viewmodels.A r48, com.quizlet.search.viewmodels.r r49, com.quizlet.search.viewmodels.D r50, com.quizlet.search.viewmodels.x r51, com.quizlet.search.viewmodels.G r52, com.quizlet.search.viewmodels.u r53, final kotlin.jvm.functions.c r54, final kotlin.jvm.functions.Function2 r55, final kotlin.jvm.functions.Function2 r56, final kotlin.jvm.functions.c r57, final kotlin.jvm.functions.c r58, final kotlin.jvm.functions.Function2 r59, final kotlin.jvm.functions.Function1 r60, final kotlin.jvm.functions.c r61, final kotlin.jvm.functions.Function2 r62, final kotlin.jvm.functions.Function1 r63, long r64, androidx.compose.runtime.InterfaceC0806l r66, final int r67) {
        /*
            Method dump skipped, instructions count: 1519
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3261t0.c(java.lang.String, com.quizlet.assembly.compose.modals.x, androidx.compose.ui.q, java.lang.String, com.quizlet.search.data.c, androidx.compose.foundation.layout.z0, com.quizlet.search.viewmodels.A, com.quizlet.search.viewmodels.r, com.quizlet.search.viewmodels.D, com.quizlet.search.viewmodels.x, com.quizlet.search.viewmodels.G, com.quizlet.search.viewmodels.u, kotlin.jvm.functions.c, kotlin.jvm.functions.Function2, kotlin.jvm.functions.Function2, kotlin.jvm.functions.c, kotlin.jvm.functions.c, kotlin.jvm.functions.Function2, kotlin.jvm.functions.Function1, kotlin.jvm.functions.c, kotlin.jvm.functions.Function2, kotlin.jvm.functions.Function1, long, androidx.compose.runtime.l, int):void");
    }
}

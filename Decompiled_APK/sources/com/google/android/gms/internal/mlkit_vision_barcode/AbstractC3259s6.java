package com.google.android.gms.internal.mlkit_vision_barcode;

import android.view.MotionEvent;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.foundation.layout.C0380d;
import androidx.compose.foundation.layout.C0392j;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3745v5;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.text.StringsKt;

/* renamed from: com.google.android.gms.internal.mlkit_vision_barcode.s6, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3259s6 {
    public static final /* synthetic */ int a = 0;

    public static final void a(com.quizlet.features.infra.folder.tag.screenstates.k kVar, Function1 function1, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(2116085122);
        if ((i & 6) == 0) {
            i2 = (c0814p.f(kVar) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.h(function1) ? 32 : 16;
        }
        if ((i2 & 19) == 18 && c0814p.x()) {
            c0814p.Q();
        } else {
            int size = kVar.a.size();
            C0380d c0380d = AbstractC0398m.a;
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            mVar.u();
            float f = com.quizlet.ui.resources.designsystem.generated.j.g;
            C0392j c0392jG = AbstractC0398m.g(f);
            mVar.u();
            AbstractC0382e.b(size, null, c0392jG, AbstractC0398m.g(f), 0, 0, null, androidx.compose.runtime.internal.e.e(-2052821415, new com.quizlet.features.infra.folder.tag.composable.g(0, kVar, function1), c0814p), c0814p, 12582912, 114);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.progress.a(kVar, function1, i, 9);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:101:? A[RETURN, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:23:0x0042  */
    /* JADX WARN: Removed duplicated region for block: B:26:0x0048  */
    /* JADX WARN: Removed duplicated region for block: B:35:0x0061  */
    /* JADX WARN: Removed duplicated region for block: B:39:0x006f  */
    /* JADX WARN: Removed duplicated region for block: B:41:0x0073  */
    /* JADX WARN: Removed duplicated region for block: B:42:0x0075  */
    /* JADX WARN: Removed duplicated region for block: B:45:0x0079  */
    /* JADX WARN: Removed duplicated region for block: B:49:0x0097  */
    /* JADX WARN: Removed duplicated region for block: B:53:0x00b0  */
    /* JADX WARN: Removed duplicated region for block: B:67:0x0115  */
    /* JADX WARN: Removed duplicated region for block: B:68:0x0119  */
    /* JADX WARN: Removed duplicated region for block: B:73:0x013c  */
    /* JADX WARN: Removed duplicated region for block: B:76:0x01b3  */
    /* JADX WARN: Removed duplicated region for block: B:78:0x01b9  */
    /* JADX WARN: Removed duplicated region for block: B:85:0x01d9  */
    /* JADX WARN: Removed duplicated region for block: B:88:0x01f6  */
    /* JADX WARN: Removed duplicated region for block: B:92:0x0207  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void b(com.quizlet.features.infra.folder.tag.screenstates.k r21, androidx.compose.ui.q r22, kotlin.jvm.functions.Function1 r23, androidx.compose.runtime.InterfaceC0806l r24, int r25, int r26) {
        /*
            Method dump skipped, instructions count: 533
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3259s6.b(com.quizlet.features.infra.folder.tag.screenstates.k, androidx.compose.ui.q, kotlin.jvm.functions.Function1, androidx.compose.runtime.l, int, int):void");
    }

    public static final void c(Function1 function1, String str, com.quizlet.features.infra.folder.tag.screenstates.k kVar, androidx.compose.ui.q qVar, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1315149182);
        if ((i & 6) == 0) {
            i2 = (c0814p.h(function1) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.f(str) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p.f(kVar) ? 256 : 128;
        }
        if ((i & 3072) == 0) {
            i2 |= c0814p.f(qVar) ? 2048 : 1024;
        }
        if ((i2 & 1171) == 1170 && c0814p.x()) {
            c0814p.Q();
        } else {
            Object[] objArr = new Object[0];
            c0814p.X(-1406878369);
            Object objI = c0814p.I();
            Object obj = C0804k.a;
            if (objI == obj) {
                objI = new com.quizlet.features.emailconfirmation.ui.composables.c(18);
                c0814p.i0(objI);
            }
            c0814p.p(false);
            InterfaceC0773a0 interfaceC0773a0 = (InterfaceC0773a0) L4.d(objArr, null, (Function0) objI, c0814p, 3072, 6);
            Object[] objArr2 = new Object[0];
            c0814p.X(-1406876414);
            Object objI2 = c0814p.I();
            if (objI2 == obj) {
                objI2 = new com.quizlet.features.emailconfirmation.ui.composables.c(19);
                c0814p.i0(objI2);
            }
            c0814p.p(false);
            InterfaceC0773a0 interfaceC0773a02 = (InterfaceC0773a0) L4.d(objArr2, null, (Function0) objI2, c0814p, 3072, 6);
            c0814p.X(-1406874743);
            int i3 = i2 & 14;
            boolean zF = (i3 == 4) | c0814p.f(interfaceC0773a0);
            Object objI3 = c0814p.I();
            if (zF || objI3 == obj) {
                objI3 = new com.quizlet.features.infra.folder.tag.composable.f(0, interfaceC0773a0, function1);
                c0814p.i0(objI3);
            }
            Function0 function0 = (Function0) objI3;
            c0814p.p(false);
            String str2 = (String) interfaceC0773a0.getValue();
            String strD = AbstractC3106b5.d(c0814p, R.string.new_tag_hint);
            c0814p.X(-1406854817);
            androidx.compose.runtime.internal.d dVarE = (!((Boolean) interfaceC0773a02.getValue()).booleanValue() || StringsKt.O((String) interfaceC0773a0.getValue()) || ((String) interfaceC0773a0.getValue()).length() < 1) ? null : androidx.compose.runtime.internal.e.e(-1875311391, new com.quizlet.assembly.compose.input.m(function0, kVar), c0814p);
            c0814p.p(false);
            androidx.compose.material3.A4 a4K = AbstractC3745v5.k(com.quizlet.assembly.compose.input.n.a, c0814p, 0);
            androidx.compose.material3.A4 a4A = a4K.a(a4K.a, a4K.b, a4K.c, a4K.d, a4K.e, a4K.f, a4K.g, a4K.h, a4K.i, a4K.j, a4K.k, ((-14337) & 2048) != 0 ? a4K.l : 0L, ((-14337) & 4096) != 0 ? a4K.m : 0L, ((-14337) & 8192) != 0 ? a4K.n : 0L, a4K.o, a4K.p, a4K.q, a4K.r, a4K.s, a4K.t, a4K.u, a4K.v, ((-14337) & 4194304) != 0 ? a4K.w : ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).b.b(), a4K.x, a4K.y, a4K.z, a4K.A, a4K.B, a4K.C, a4K.D, a4K.E, a4K.F, a4K.G, a4K.H, a4K.I, a4K.J, a4K.K, a4K.L, a4K.M, a4K.N, a4K.O, a4K.P, a4K.Q);
            c0814p.X(-1406838299);
            boolean zF2 = c0814p.f(interfaceC0773a02);
            Object objI4 = c0814p.I();
            if (zF2 || objI4 == obj) {
                objI4 = new com.quizlet.assembly.compose.modals.t(interfaceC0773a02, 6);
                c0814p.i0(objI4);
            }
            c0814p.p(false);
            androidx.compose.ui.q qVarX = androidx.compose.ui.focus.a.x(qVar, (Function1) objI4);
            c0814p.X(-1406869263);
            boolean zF3 = (i3 == 4) | c0814p.f(interfaceC0773a0);
            Object objI5 = c0814p.I();
            if (zF3 || objI5 == obj) {
                objI5 = new com.quizlet.features.flashcards.settings.ui.e(5, interfaceC0773a0, function1);
                c0814p.i0(objI5);
            }
            Function1 function12 = (Function1) objI5;
            c0814p.p(false);
            c0814p.X(-1406862071);
            boolean zF4 = ((i2 & 896) == 256) | c0814p.f(interfaceC0773a0) | c0814p.f(function0);
            Object objI6 = c0814p.I();
            if (zF4 || objI6 == obj) {
                objI6 = new androidx.work.impl.utils.q(kVar, function0, interfaceC0773a0, 15);
                c0814p.i0(objI6);
            }
            c0814p.p(false);
            AbstractC3745v5.a(str2, qVarX, function12, strD, null, 0, 0, null, null, 7, 0, (Function0) objI6, str, false, false, null, 0, null, DefinitionKt.NO_Float_VALUE, a4A, null, dVarE, c0814p, 0, ((i2 << 6) & 7168) | 6, 0, 3132400);
            c0814p = c0814p;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.menu.i(function1, str, kVar, qVar, i);
        }
    }

    public static final void d(kotlinx.collections.immutable.e eVar, Function1 function1, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-693911249);
        if ((i & 6) == 0) {
            i2 = (c0814p.f(eVar) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.h(function1) ? 32 : 16;
        }
        if ((i2 & 19) == 18 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            mVar.p();
            float f = com.quizlet.ui.resources.designsystem.generated.j.j;
            mVar.s();
            androidx.compose.material3.Q4.b(AbstractC3106b5.d(c0814p, R.string.new_tag_recommended_title), AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, f, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.h, 5), ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).b.f(), 0L, null, 0L, null, 0L, 0, false, 0, 0, null, ((com.quizlet.themes.f) c0814p.j(com.quizlet.themes.w.a)).l, c0814p, 0, 0, 65528);
            c0814p = c0814p;
            int size = eVar.size();
            C0380d c0380d = AbstractC0398m.a;
            mVar.u();
            float f2 = com.quizlet.ui.resources.designsystem.generated.j.g;
            C0392j c0392jG = AbstractC0398m.g(f2);
            mVar.u();
            AbstractC0382e.b(size, null, c0392jG, AbstractC0398m.g(f2), 0, 0, null, androidx.compose.runtime.internal.e.e(-1652175368, new com.quizlet.features.infra.folder.tag.composable.g(1, eVar, function1), c0814p), c0814p, 12582912, 114);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.progress.a(eVar, function1, i, 8);
        }
    }

    public static final void e(int i, InterfaceC0806l interfaceC0806l, Function0 function0, boolean z) {
        Function0 function02;
        boolean z2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-404682516);
        int i2 = (c0814p.h(function0) ? 4 : 2) | i | (c0814p.g(z) ? 32 : 16);
        if ((i2 & 19) == 18 && c0814p.x()) {
            c0814p.Q();
            function02 = function0;
            z2 = z;
        } else {
            function02 = function0;
            z2 = z;
            androidx.compose.material3.Z1.h(function02, androidx.compose.ui.platform.N.G(androidx.compose.ui.n.b, "AddTagTestTag"), z2, null, com.quizlet.features.infra.folder.tag.composable.b.a, c0814p, (i2 & 14) | 196656 | ((i2 << 3) & 896), 24);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.input.c(i, 1, function02, z2);
        }
    }

    public static boolean f(MotionEvent motionEvent, int i) {
        return (motionEvent.getSource() & i) == i;
    }
}

package com.google.android.gms.internal.mlkit_vision_document_scanner;

import android.graphics.PorterDuffColorFilter;
import android.os.Build;
import androidx.compose.animation.core.AbstractC0240f;
import androidx.compose.animation.core.C0238e;
import androidx.compose.foundation.AbstractC0460p;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.foundation.layout.AbstractC0409s;
import androidx.compose.foundation.layout.C0380d;
import androidx.compose.foundation.layout.C0386g;
import androidx.compose.foundation.layout.LayoutWeightElement;
import androidx.compose.material3.AbstractC0587a3;
import androidx.compose.material3.AbstractC0590b0;
import androidx.compose.material3.AbstractC0666j3;
import androidx.compose.material3.AbstractC0686n;
import androidx.compose.runtime.AbstractC0809m0;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.C0839z;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.graphics.C0853m;
import androidx.compose.ui.graphics.C0854n;
import androidx.compose.ui.graphics.C0861v;
import androidx.compose.ui.graphics.vector.AbstractC0863b;
import androidx.compose.ui.graphics.vector.C0866e;
import androidx.compose.ui.graphics.vector.C0867f;
import androidx.compose.ui.graphics.vector.C0872k;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3249r5;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3277v0;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3409x1;
import com.quizlet.assembly.compose.buttons.C4089n;
import com.quizlet.assembly.compose.buttons.C4096v;
import com.quizlet.features.achievements.ui.composables.C4214a;
import com.quizlet.features.folders.composables.C4252h;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.ui.library.AbstractC4645c;
import com.quizlet.quizletandroid.ui.library.C4643a;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.ArrayList;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_document_scanner.h5, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3634h5 {
    /* JADX WARN: Removed duplicated region for block: B:101:0x0144  */
    /* JADX WARN: Removed duplicated region for block: B:106:0x0162  */
    /* JADX WARN: Removed duplicated region for block: B:110:0x017e  */
    /* JADX WARN: Removed duplicated region for block: B:112:0x0182  */
    /* JADX WARN: Removed duplicated region for block: B:116:0x019e  */
    /* JADX WARN: Removed duplicated region for block: B:119:0x01b1  */
    /* JADX WARN: Removed duplicated region for block: B:120:0x01b6  */
    /* JADX WARN: Removed duplicated region for block: B:123:0x01cc  */
    /* JADX WARN: Removed duplicated region for block: B:126:0x0201  */
    /* JADX WARN: Removed duplicated region for block: B:129:0x023f  */
    /* JADX WARN: Removed duplicated region for block: B:130:0x0242  */
    /* JADX WARN: Removed duplicated region for block: B:134:0x024d  */
    /* JADX WARN: Removed duplicated region for block: B:137:0x026c  */
    /* JADX WARN: Removed duplicated region for block: B:138:0x026f  */
    /* JADX WARN: Removed duplicated region for block: B:142:0x027a  */
    /* JADX WARN: Removed duplicated region for block: B:145:0x02c9  */
    /* JADX WARN: Removed duplicated region for block: B:146:0x02cc  */
    /* JADX WARN: Removed duplicated region for block: B:149:0x02eb  */
    /* JADX WARN: Removed duplicated region for block: B:150:0x02ee  */
    /* JADX WARN: Removed duplicated region for block: B:159:0x0305  */
    /* JADX WARN: Removed duplicated region for block: B:162:0x0317  */
    /* JADX WARN: Removed duplicated region for block: B:163:0x031a  */
    /* JADX WARN: Removed duplicated region for block: B:167:0x0328  */
    /* JADX WARN: Removed duplicated region for block: B:173:0x0344  */
    /* JADX WARN: Removed duplicated region for block: B:177:0x0393  */
    /* JADX WARN: Removed duplicated region for block: B:179:? A[RETURN, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:26:0x0048  */
    /* JADX WARN: Removed duplicated region for block: B:28:0x004d  */
    /* JADX WARN: Removed duplicated region for block: B:37:0x0063  */
    /* JADX WARN: Removed duplicated region for block: B:39:0x0068  */
    /* JADX WARN: Removed duplicated region for block: B:48:0x007e  */
    /* JADX WARN: Removed duplicated region for block: B:50:0x0083  */
    /* JADX WARN: Removed duplicated region for block: B:59:0x009c  */
    /* JADX WARN: Removed duplicated region for block: B:60:0x00a1  */
    /* JADX WARN: Removed duplicated region for block: B:69:0x00ba  */
    /* JADX WARN: Removed duplicated region for block: B:72:0x00c4  */
    /* JADX WARN: Removed duplicated region for block: B:73:0x00c9  */
    /* JADX WARN: Removed duplicated region for block: B:82:0x00e8  */
    /* JADX WARN: Removed duplicated region for block: B:86:0x00fd  */
    /* JADX WARN: Removed duplicated region for block: B:93:0x0121  */
    /* JADX WARN: Removed duplicated region for block: B:94:0x0123  */
    /* JADX WARN: Removed duplicated region for block: B:96:0x0126  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void a(final kotlinx.collections.immutable.b r28, boolean r29, kotlin.jvm.functions.Function1 r30, kotlin.jvm.functions.Function1 r31, kotlin.jvm.functions.Function1 r32, kotlin.jvm.functions.Function1 r33, com.quizlet.quizletandroid.util.o r34, boolean r35, androidx.compose.runtime.InterfaceC0806l r36, int r37, int r38) {
        /*
            Method dump skipped, instructions count: 928
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3634h5.a(kotlinx.collections.immutable.b, boolean, kotlin.jvm.functions.Function1, kotlin.jvm.functions.Function1, kotlin.jvm.functions.Function1, kotlin.jvm.functions.Function1, com.quizlet.quizletandroid.util.o, boolean, androidx.compose.runtime.l, int, int):void");
    }

    public static final void b(String str, androidx.compose.ui.q qVar, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1629233996);
        int i2 = i | (c0814p.f(str) ? 4 : 2) | (c0814p.f(qVar) ? 32 : 16);
        if ((i2 & 19) == 18 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.ui.g gVar = androidx.compose.ui.b.n;
            C0386g c0386g = AbstractC0398m.e;
            androidx.compose.ui.q qVarG = qVar.g(androidx.compose.foundation.layout.K0.c);
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            mVar.p();
            androidx.compose.ui.q qVarW = AbstractC0382e.w(qVarG, com.quizlet.ui.resources.designsystem.generated.j.j, DefinitionKt.NO_Float_VALUE, 2);
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(c0386g, gVar, c0814p, 54);
            int i3 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, qVarW);
            InterfaceC0915k.D0.getClass();
            C0913i c0913i = C0914j.b;
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0776c.E(c0814p, bA, C0914j.f);
            C0776c.E(c0814p, interfaceC0803j0L, C0914j.e);
            C0912h c0912h = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i3))) {
                android.support.v4.media.session.a.z(i3, c0814p, i3, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            C0867f c0867fH = com.google.android.gms.internal.mlkit_vision_barcode.A0.h();
            androidx.compose.runtime.B b = com.quizlet.themes.g.a;
            long jF = ((com.quizlet.themes.b) c0814p.j(b)).b.f();
            C0853m c0853m = new C0853m(jF, 5, Build.VERSION.SDK_INT >= 29 ? C0854n.a.a(jF, 5) : new PorterDuffColorFilter(androidx.compose.ui.graphics.F.A(jF), androidx.compose.ui.graphics.F.E(5)));
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            mVar.g();
            AbstractC0460p.d(c0867fH, null, androidx.compose.foundation.layout.K0.k(nVar, com.quizlet.ui.resources.designsystem.generated.h.h), c0853m, c0814p, 48, 56);
            androidx.compose.ui.text.L l = ((com.quizlet.themes.f) c0814p.j(com.quizlet.themes.w.b)).p;
            long jF2 = ((com.quizlet.themes.b) c0814p.j(b)).b.f();
            mVar.s();
            androidx.compose.material3.Q4.b(str, AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.h, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), jF2, 0L, null, 0L, new androidx.compose.ui.text.style.i(3), 0L, 0, false, 0, 0, null, l, c0814p, i2 & 14, 0, 65016);
            c0814p = c0814p;
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C4214a(str, qVar, i, 7);
        }
    }

    public static final void c(int i, InterfaceC0806l interfaceC0806l, androidx.compose.ui.q qVar, String str, Function1 function1) {
        C0814p c0814p;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-1401524912);
        int i2 = i | (c0814p2.f(str) ? 4 : 2) | (c0814p2.h(function1) ? 256 : 128);
        if ((i2 & 147) == 146 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            androidx.compose.material3.D4 d4 = androidx.compose.material3.D4.a;
            androidx.compose.runtime.B b = com.quizlet.themes.g.a;
            c0814p = c0814p2;
            androidx.compose.material3.K4.b(str, function1, qVar, false, false, null, AbstractC4645c.a, null, null, null, null, false, null, null, null, true, 0, 0, null, null, androidx.compose.material3.D4.c(0L, 0L, 0L, 0L, ((com.quizlet.themes.b) c0814p2.j(b)).b.g(), ((com.quizlet.themes.b) c0814p2.j(b)).b.g(), ((com.quizlet.themes.b) c0814p2.j(b)).b.g(), 0L, 0L, 0L, null, ((com.quizlet.themes.b) c0814p2.j(b)).b.e(), 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, c0814p, 2147481487), c0814p, ((i2 >> 3) & ContentType.LONG_FORM_ON_DEMAND) | (i2 & 14) | 1572864 | 384, 12582912, 0, 4063160);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C4252h(i, 1, qVar, str, function1);
        }
    }

    public static final void d(int i, InterfaceC0806l interfaceC0806l, androidx.compose.ui.q qVar, String str, Function1 function1) {
        C0814p c0814p;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-1720196261);
        int i2 = (c0814p2.f(qVar) ? 4 : 2) | i | (c0814p2.f(str) ? 32 : 16) | (c0814p2.h(function1) ? 256 : 128);
        if ((i2 & 147) == 146 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            androidx.compose.runtime.V v = C0804k.a;
            c0814p2.X(-1767070635);
            Object objI = c0814p2.I();
            if (objI == v) {
                objI = new androidx.compose.ui.focus.p();
                c0814p2.i0(objI);
            }
            c0814p2.p(false);
            androidx.compose.ui.text.L l = ((com.quizlet.themes.f) c0814p2.j(com.quizlet.themes.w.a)).k;
            androidx.compose.ui.q qVarK = androidx.compose.ui.focus.a.k(androidx.compose.foundation.layout.K0.c(qVar, 1.0f), (androidx.compose.ui.focus.p) objI);
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            mVar.u();
            androidx.compose.ui.q qVarY = AbstractC0382e.y(qVarK, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.g, DefinitionKt.NO_Float_VALUE, 11);
            mVar.d();
            androidx.compose.foundation.shape.d dVarA = androidx.compose.foundation.shape.e.a(com.quizlet.ui.resources.designsystem.generated.f.g);
            androidx.compose.material3.P2 p2 = androidx.compose.material3.P2.a;
            androidx.compose.runtime.B b = com.quizlet.themes.g.a;
            long jG = ((com.quizlet.themes.b) c0814p2.j(b)).b.g();
            long jG2 = ((com.quizlet.themes.b) c0814p2.j(b)).b.g();
            long jM = ((com.quizlet.themes.b) c0814p2.j(b)).b.m();
            long jF = ((com.quizlet.themes.b) c0814p2.j(b)).b.f();
            long j = C0861v.g;
            androidx.compose.material3.A4 a4A = androidx.compose.material3.P2.c((androidx.compose.material3.Z) c0814p2.j(AbstractC0590b0.a), c0814p2).a(j, j, j, j, jG, jG2, j, j, j, j, null, jM, jF, j, j, j, j, j, j, j, j, j, j, j, j, j, j, j, j, j, j, j, j, j, j, j, j, j, j, j, j, j, j);
            c0814p2.X(-1767047918);
            boolean z = (i2 & 896) == 256;
            Object objI2 = c0814p2.I();
            if (z || objI2 == v) {
                objI2 = new com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.composables.l(25, function1);
                c0814p2.i0(objI2);
            }
            c0814p2.p(false);
            c0814p = c0814p2;
            AbstractC0587a3.b(str, (Function1) objI2, qVarY, false, l, AbstractC4645c.b, AbstractC4645c.c, androidx.compose.runtime.internal.e.e(-1474505852, new com.quizlet.features.practicetest.results.i(19, (Object) str, function1), c0814p2), null, null, null, true, 0, 0, dVarA, a4A, c0814p, ((i2 >> 3) & 14) | 918552576);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C4252h(qVar, str, function1, i);
        }
    }

    public static final void e(AbstractC3698p5 data, Function0 function0, Function1 function1, Function1 function12, Function1 function13, Function1 function14, boolean z, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p;
        Intrinsics.checkNotNullParameter(data, "data");
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-1574835409);
        int i2 = i | (c0814p2.f(data) ? 4 : 2) | (c0814p2.h(function0) ? 32 : 16) | (c0814p2.h(function1) ? 256 : 128) | (c0814p2.h(function12) ? 2048 : 1024) | (c0814p2.h(function13) ? 16384 : 8192) | (c0814p2.h(function14) ? 131072 : 65536) | (c0814p2.g(z) ? 1048576 : 524288);
        if ((599187 & i2) == 599186 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else if (data instanceof com.quizlet.quizletandroid.ui.library.data.G) {
            c0814p2.X(-783597122);
            com.quizlet.quizletandroid.ui.library.data.G g = (com.quizlet.quizletandroid.ui.library.data.G) data;
            c0814p = c0814p2;
            a(g.a, g.b, function1, function12, function13, function14, null, z, c0814p, (524160 & i2) | ((i2 << 3) & 29360128), 64);
            c0814p.p(false);
        } else {
            c0814p = c0814p2;
            if (Intrinsics.b(data, com.quizlet.quizletandroid.ui.library.data.I.a)) {
                c0814p.X(-783583802);
                AbstractC3249r5.a(null, ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).b.g(), c0814p, 0, 1);
                c0814p.p(false);
            } else {
                if (!Intrinsics.b(data, com.quizlet.quizletandroid.ui.library.data.H.a)) {
                    throw com.google.android.gms.measurement.internal.Z.j(-783598288, c0814p, false);
                }
                c0814p.X(1478826537);
                com.quizlet.themes.e.a(c0814p).d.getClass();
                c0814p.X(506397308);
                androidx.compose.ui.graphics.painter.b bVarA = com.google.android.gms.internal.mlkit_vision_barcode.Z4.a(R.drawable.ic_brand_create, c0814p, 0);
                c0814p.p(false);
                AbstractC3611e6.a(bVarA, AbstractC3106b5.d(c0814p, R.string.library_create_study_set_description), AbstractC3106b5.d(c0814p, R.string.library_create_study_set_button), null, AbstractC3106b5.d(c0814p, R.string.library_create_study_set_content_description), function0, c0814p, (i2 << 12) & 458752);
                c0814p.p(false);
            }
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.explanations.questiondetail.ui.composables.k(data, function0, function1, function12, function13, function14, z, i);
        }
    }

    public static final void f(C4089n state, androidx.compose.ui.q qVar, Function1 function1, InterfaceC0806l interfaceC0806l, int i) {
        Object eVar;
        Object obj;
        C0814p c0814p;
        Intrinsics.checkNotNullParameter(state, "state");
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-767668072);
        int i2 = i | (c0814p2.f(state) ? 4 : 2) | (c0814p2.f(qVar) ? 32 : 16) | (c0814p2.h(function1) ? 256 : 128);
        if ((i2 & 147) == 146 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            Object obj2 = C0804k.a;
            Object objI = c0814p2.I();
            if (objI == obj2) {
                objI = android.support.v4.media.session.a.c(C0776c.n(kotlin.coroutines.n.a, c0814p2), c0814p2);
            }
            Object obj3 = ((C0839z) objI).a;
            Object obj4 = (androidx.lifecycle.J) c0814p2.j(androidx.lifecycle.compose.g.a);
            c0814p2.X(-1169130398);
            Object objI2 = c0814p2.I();
            if (objI2 == obj2) {
                c0814p2.i0(function1);
                objI2 = function1;
            }
            Function1 function12 = (Function1) objI2;
            Object objG = com.google.android.gms.measurement.internal.Z.g(-1169129041, c0814p2, false);
            if (objG == obj2) {
                objG = C0776c.z(Boolean.TRUE);
                c0814p2.i0(objG);
            }
            InterfaceC0773a0 interfaceC0773a0 = (InterfaceC0773a0) objG;
            Object objG2 = com.google.android.gms.measurement.internal.Z.g(-1169127302, c0814p2, false);
            if (objG2 == obj2) {
                state.getClass();
                objG2 = AbstractC0240f.a(DefinitionKt.NO_Float_VALUE);
                c0814p2.i0(objG2);
            }
            C0238e c0238e = (C0238e) objG2;
            c0814p2.p(false);
            state.getClass();
            kotlin.jvm.internal.G g = new kotlin.jvm.internal.G();
            g.a = 1.0f;
            Boolean bool = (Boolean) interfaceC0773a0.getValue();
            bool.booleanValue();
            C0776c.f(c0814p2, bool, new com.quizlet.assembly.compose.buttons.a0(g, c0238e, function12, state, interfaceC0773a0, null));
            c0814p2.X(-1169100973);
            boolean zH = c0814p2.h(obj4) | c0814p2.h(c0238e);
            Object objI3 = c0814p2.I();
            if (zH || objI3 == obj2) {
                obj = obj4;
                eVar = new androidx.navigation.internal.e(obj, function12, c0238e, interfaceC0773a0, 1);
                c0814p2.i0(eVar);
            } else {
                eVar = objI3;
                obj = obj4;
            }
            c0814p2.p(false);
            C0776c.d(obj, (Function1) eVar, c0814p2);
            c0814p2.X(-1169066909);
            boolean zH2 = c0814p2.h(obj3) | c0814p2.h(c0238e);
            Object objI4 = c0814p2.I();
            if (zH2 || objI4 == obj2) {
                Object oVar = new androidx.work.impl.utils.o(obj3, function12, c0238e, interfaceC0773a0, 3);
                c0814p2.i0(oVar);
                objI4 = oVar;
            }
            Function0 function0 = (Function0) objI4;
            c0814p2.p(false);
            c0814p2.X(-1169073112);
            boolean z = (i2 & 14) == 4;
            Object objI5 = c0814p2.I();
            if (z || objI5 == obj2) {
                objI5 = new androidx.work.impl.utils.q(function12, state, interfaceC0773a0, 6);
                c0814p2.i0(objI5);
            }
            c0814p2.p(false);
            androidx.compose.ui.q qVarG = androidx.compose.ui.platform.N.G(AbstractC0460p.n(qVar, function0, (Function0) objI5, 47), "linearProgressTag");
            AbstractC0809m0 abstractC0809m0 = com.quizlet.themes.g.a;
            long jK = ((com.quizlet.themes.b) c0814p2.j(abstractC0809m0)).K();
            ((com.quizlet.themes.b) c0814p2.j(abstractC0809m0)).c.getClass();
            long j = com.quizlet.ui.resources.designsystem.generated.d.o;
            float f = 0;
            c0814p2.X(-1169051839);
            boolean zH3 = c0814p2.h(c0238e);
            Object objI6 = c0814p2.I();
            if (zH3 || objI6 == obj2) {
                objI6 = new com.braze.requests.framework.o(c0238e, 20);
                c0814p2.i0(objI6);
            }
            Function0 function02 = (Function0) objI6;
            Object objG3 = com.google.android.gms.measurement.internal.Z.g(-1169044496, c0814p2, false);
            if (objG3 == obj2) {
                objG3 = new com.quizlet.assembly.compose.buttons.Z(0);
                c0814p2.i0(objG3);
            }
            c0814p2.p(false);
            c0814p = c0814p2;
            AbstractC0666j3.b(function02, qVarG, jK, j, 0, f, (Function1) objG3, c0814p, 1769472, 0);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new androidx.lifecycle.compose.e(i, 2, state, qVar, function1);
        }
    }

    public static final void g(int i, Function1 function1, androidx.compose.ui.q qVar, boolean z, InterfaceC0806l interfaceC0806l, int i2) {
        boolean z2;
        InterfaceC0773a0 interfaceC0773a0;
        androidx.compose.runtime.V v;
        InterfaceC0773a0 interfaceC0773a02;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-683881361);
        if (((i2 | (c0814p.d(i) ? 4 : 2) | (c0814p.h(function1) ? 32 : 16) | (c0814p.f(qVar) ? 256 : 128) | (c0814p.g(z) ? 2048 : 1024)) & 1171) == 1170 && c0814p.x()) {
            c0814p.Q();
        } else {
            kotlinx.collections.immutable.e eVarH = AbstractC3409x1.h(AbstractC3106b5.d(c0814p, R.string.library_study_set_dropdown_menu_item_all), AbstractC3106b5.d(c0814p, R.string.library_study_set_dropdown_menu_item_created), AbstractC3106b5.d(c0814p, R.string.library_study_set_dropdown_menu_item_studied), AbstractC3106b5.d(c0814p, R.string.library_study_set_dropdown_menu_item_downloaded));
            c0814p.X(1802705214);
            Object objI = c0814p.I();
            androidx.compose.runtime.V v2 = C0804k.a;
            if (objI == v2) {
                objI = C0776c.z(Boolean.FALSE);
                c0814p.i0(objI);
            }
            InterfaceC0773a0 interfaceC0773a03 = (InterfaceC0773a0) objI;
            c0814p.p(false);
            androidx.compose.ui.layout.K kE = AbstractC0409s.e(androidx.compose.ui.b.a, false);
            int i3 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, qVar);
            InterfaceC0915k.D0.getClass();
            C0913i c0913i = C0914j.b;
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0776c.E(c0814p, kE, C0914j.f);
            C0776c.E(c0814p, interfaceC0803j0L, C0914j.e);
            C0912h c0912h = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i3))) {
                android.support.v4.media.session.a.z(i3, c0814p, i3, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            if (z) {
                c0814p.X(1454018419);
                String str = (String) eVarH.get(i);
                com.quizlet.assembly.compose.links.h hVar = com.quizlet.assembly.compose.links.h.a;
                com.quizlet.assembly.compose.links.b bVar = new com.quizlet.assembly.compose.links.b(C4643a.f, null, null);
                com.quizlet.themes.m.g.u();
                androidx.compose.foundation.layout.A0 a0C = AbstractC0382e.c(DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.g, 1);
                c0814p.X(-922919885);
                Object objI2 = c0814p.I();
                if (objI2 == v2) {
                    objI2 = new com.quizlet.features.practicetest.detail.composables.f(interfaceC0773a03, 23);
                    c0814p.i0(objI2);
                }
                c0814p.p(false);
                z2 = false;
                AbstractC3777z5.a(str, null, hVar, a0C, bVar, (Function0) objI2, c0814p, 196608, 2);
                c0814p.p(false);
                v = v2;
                interfaceC0773a0 = interfaceC0773a03;
            } else {
                z2 = false;
                c0814p.X(1454452357);
                String str2 = (String) eVarH.get(i);
                c0814p.X(-922910253);
                Object objI3 = c0814p.I();
                if (objI3 == v2) {
                    objI3 = new com.quizlet.features.practicetest.detail.composables.f(interfaceC0773a03, 24);
                    c0814p.i0(objI3);
                }
                Function0 function0 = (Function0) objI3;
                c0814p.p(false);
                C4096v c4096v = C4096v.a;
                C0867f c0867fB = com.google.android.gms.internal.mlkit_vision_barcode.B0.a;
                if (c0867fB == null) {
                    C0866e c0866e = new C0866e("Filled.KeyboardArrowDown", 24.0f, 24.0f, 24.0f, 24.0f, 0L, 0, false, 96);
                    kotlin.collections.K k = androidx.compose.ui.graphics.vector.I.a;
                    androidx.compose.ui.graphics.X x = new androidx.compose.ui.graphics.X(C0861v.b);
                    ArrayList arrayList = new ArrayList(32);
                    arrayList.add(new androidx.compose.ui.graphics.vector.o(7.41f, 8.59f));
                    arrayList.add(new androidx.compose.ui.graphics.vector.n(12.0f, 13.17f));
                    arrayList.add(new androidx.compose.ui.graphics.vector.v(4.59f, -4.58f));
                    arrayList.add(new androidx.compose.ui.graphics.vector.n(18.0f, 10.0f));
                    arrayList.add(new androidx.compose.ui.graphics.vector.v(-6.0f, 6.0f));
                    arrayList.add(new androidx.compose.ui.graphics.vector.v(-6.0f, -6.0f));
                    arrayList.add(new androidx.compose.ui.graphics.vector.v(1.41f, -1.41f));
                    arrayList.add(C0872k.c);
                    C0866e.a(c0866e, arrayList, x);
                    c0867fB = c0866e.b();
                    com.google.android.gms.internal.mlkit_vision_barcode.B0.a = c0867fB;
                }
                interfaceC0773a0 = interfaceC0773a03;
                v = v2;
                Y4.a(str2, null, function0, false, false, null, null, 0L, 0L, c4096v, null, AbstractC0863b.c(c0867fB, c0814p), false, c0814p, 384, 64, 5626);
                c0814p = c0814p;
                c0814p.p(false);
            }
            boolean zBooleanValue = ((Boolean) interfaceC0773a0.getValue()).booleanValue();
            c0814p.X(-922901713);
            Object objI4 = c0814p.I();
            if (objI4 == v) {
                interfaceC0773a02 = interfaceC0773a0;
                objI4 = new com.quizlet.features.practicetest.detail.composables.f(interfaceC0773a02, 25);
                c0814p.i0(objI4);
            } else {
                interfaceC0773a02 = interfaceC0773a0;
            }
            c0814p.p(z2);
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            long jN = ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).b.n();
            com.quizlet.themes.m.g.d();
            C0814p c0814p2 = c0814p;
            AbstractC0686n.a(zBooleanValue, (Function0) objI4, AbstractC0460p.f(nVar, jN, androidx.compose.foundation.shape.e.a(com.quizlet.ui.resources.designsystem.generated.f.g)), 0L, null, null, null, 0L, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, androidx.compose.runtime.internal.e.e(-375532316, new com.quizlet.explanations.questiondetail.ui.composables.s(eVarH, function1, i, interfaceC0773a02), c0814p), c0814p2, 48, 48, 2040);
            c0814p = c0814p2;
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.explanations.solution.recyclerview.step.f(i, function1, qVar, z, i2);
        }
    }

    public static final void h(String str, boolean z, InterfaceC0806l interfaceC0806l, int i) {
        String str2;
        boolean z2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-2010147707);
        int i2 = i | (c0814p.f(str) ? 4 : 2) | (c0814p.g(z) ? 32 : 16);
        if ((i2 & 19) == 18 && c0814p.x()) {
            c0814p.Q();
            str2 = str;
            z2 = z;
        } else {
            androidx.compose.ui.q qVarO = androidx.compose.foundation.layout.K0.o(androidx.compose.ui.n.b, 240);
            C0380d c0380d = AbstractC0398m.a;
            androidx.compose.ui.h hVar = androidx.compose.ui.b.j;
            androidx.compose.foundation.layout.G0 g0B = androidx.compose.foundation.layout.E0.b(c0380d, hVar, c0814p, 0);
            int i3 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, qVarO);
            InterfaceC0915k.D0.getClass();
            C0913i c0913i = C0914j.b;
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0912h c0912h = C0914j.f;
            C0776c.E(c0814p, g0B, c0912h);
            C0912h c0912h2 = C0914j.e;
            C0776c.E(c0814p, interfaceC0803j0L, c0912h2);
            C0912h c0912h3 = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i3))) {
                android.support.v4.media.session.a.z(i3, c0814p, i3, c0912h3);
            }
            C0912h c0912h4 = C0914j.d;
            C0776c.E(c0814p, qVarC, c0912h4);
            if (1.0f <= 0.0d) {
                throw new IllegalArgumentException(android.support.v4.media.session.a.i("invalid weight ", 1.0f, "; must be greater than zero").toString());
            }
            LayoutWeightElement layoutWeightElement = new LayoutWeightElement(1.0f > Float.MAX_VALUE ? Float.MAX_VALUE : 1.0f, true);
            androidx.compose.foundation.layout.G0 g0B2 = androidx.compose.foundation.layout.E0.b(c0380d, hVar, c0814p, 0);
            int i4 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L2 = c0814p.l();
            androidx.compose.ui.q qVarC2 = androidx.compose.ui.a.c(c0814p, layoutWeightElement);
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0776c.E(c0814p, g0B2, c0912h);
            C0776c.E(c0814p, interfaceC0803j0L2, c0912h2);
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i4))) {
                android.support.v4.media.session.a.z(i4, c0814p, i4, c0912h3);
            }
            C0776c.E(c0814p, qVarC2, c0912h4);
            androidx.compose.runtime.B b = com.quizlet.themes.g.a;
            androidx.compose.material3.Q4.b(str, null, ((com.quizlet.themes.b) c0814p.j(b)).b.f(), 0L, null, 0L, null, 0L, 0, false, 0, 0, null, null, c0814p, i2 & 14, 0, 131066);
            str2 = str;
            c0814p = c0814p;
            c0814p.p(true);
            c0814p.X(-377596874);
            z2 = z;
            if (z2) {
                C0867f c0867fB = AbstractC3277v0.a;
                if (c0867fB == null) {
                    C0866e c0866e = new C0866e("Filled.Check", 24.0f, 24.0f, 24.0f, 24.0f, 0L, 0, false, 96);
                    kotlin.collections.K k = androidx.compose.ui.graphics.vector.I.a;
                    androidx.compose.ui.graphics.X x = new androidx.compose.ui.graphics.X(C0861v.b);
                    ArrayList arrayList = new ArrayList(32);
                    arrayList.add(new androidx.compose.ui.graphics.vector.o(9.0f, 16.17f));
                    arrayList.add(new androidx.compose.ui.graphics.vector.n(4.83f, 12.0f));
                    arrayList.add(new androidx.compose.ui.graphics.vector.v(-1.42f, 1.41f));
                    arrayList.add(new androidx.compose.ui.graphics.vector.n(9.0f, 19.0f));
                    arrayList.add(new androidx.compose.ui.graphics.vector.n(21.0f, 7.0f));
                    arrayList.add(new androidx.compose.ui.graphics.vector.v(-1.41f, -1.41f));
                    arrayList.add(C0872k.c);
                    C0866e.a(c0866e, arrayList, x);
                    c0867fB = c0866e.b();
                    AbstractC3277v0.a = c0867fB;
                }
                long jF = ((com.quizlet.themes.b) c0814p.j(b)).b.f();
                AbstractC0460p.d(c0867fB, null, null, new C0853m(jF, 5, Build.VERSION.SDK_INT >= 29 ? C0854n.a.a(jF, 5) : new PorterDuffColorFilter(androidx.compose.ui.graphics.F.A(jF), androidx.compose.ui.graphics.F.E(5))), c0814p, 48, 60);
            }
            c0814p.p(false);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new androidx.navigation.compose.internal.a(str2, i, z2);
        }
    }
}

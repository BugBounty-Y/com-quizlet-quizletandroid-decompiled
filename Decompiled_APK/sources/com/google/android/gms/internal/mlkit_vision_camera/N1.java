package com.google.android.gms.internal.mlkit_vision_camera;

import androidx.compose.foundation.AbstractC0460p;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.foundation.layout.C0380d;
import androidx.compose.foundation.layout.LayoutWeightElement;
import androidx.compose.foundation.text.C0490g0;
import androidx.compose.material3.A4;
import androidx.compose.material3.K4;
import androidx.compose.material3.Q4;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.graphics.C0861v;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import androidx.compose.ui.q;
import androidx.compose.ui.text.input.A;
import androidx.navigation.C1287i;
import androidx.navigation.C1289k;
import androidx.navigation.C1301x;
import androidx.navigation.compose.C1275h;
import androidx.navigation.compose.C1276i;
import com.braze.C1483i;
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.google.android.gms.internal.mlkit_vision_barcode.L4;
import com.google.android.gms.internal.mlkit_vision_camera.N1;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3745v5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3777z5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.S4;
import com.google.android.gms.internal.mlkit_vision_document_scanner.W4;
import com.quizlet.features.achievements.ui.composables.C4218e;
import com.quizlet.generated.enums.EnumC4533y0;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.C4950i;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class N1 {
    /* JADX WARN: Removed duplicated region for block: B:106:0x0145  */
    /* JADX WARN: Removed duplicated region for block: B:107:0x0148  */
    /* JADX WARN: Removed duplicated region for block: B:110:0x0152  */
    /* JADX WARN: Removed duplicated region for block: B:111:0x0155  */
    /* JADX WARN: Removed duplicated region for block: B:118:0x016e  */
    /* JADX WARN: Removed duplicated region for block: B:119:0x0174  */
    /* JADX WARN: Removed duplicated region for block: B:132:0x01ae  */
    /* JADX WARN: Removed duplicated region for block: B:141:0x01f3  */
    /* JADX WARN: Removed duplicated region for block: B:142:0x01f5  */
    /* JADX WARN: Removed duplicated region for block: B:143:0x01f8  */
    /* JADX WARN: Removed duplicated region for block: B:145:0x01fb  */
    /* JADX WARN: Removed duplicated region for block: B:147:0x01fe  */
    /* JADX WARN: Removed duplicated region for block: B:150:0x0203  */
    /* JADX WARN: Removed duplicated region for block: B:151:0x020d  */
    /* JADX WARN: Removed duplicated region for block: B:153:0x0212  */
    /* JADX WARN: Removed duplicated region for block: B:154:0x0215  */
    /* JADX WARN: Removed duplicated region for block: B:156:0x0219  */
    /* JADX WARN: Removed duplicated region for block: B:161:0x023c  */
    /* JADX WARN: Removed duplicated region for block: B:163:0x0242  */
    /* JADX WARN: Removed duplicated region for block: B:167:0x026c  */
    /* JADX WARN: Removed duplicated region for block: B:170:0x0290  */
    /* JADX WARN: Removed duplicated region for block: B:171:0x0293  */
    /* JADX WARN: Removed duplicated region for block: B:175:0x029c  */
    /* JADX WARN: Removed duplicated region for block: B:179:0x02c2  */
    /* JADX WARN: Removed duplicated region for block: B:182:0x02e3  */
    /* JADX WARN: Removed duplicated region for block: B:185:0x031c  */
    /* JADX WARN: Removed duplicated region for block: B:188:0x0350  */
    /* JADX WARN: Removed duplicated region for block: B:189:0x0353  */
    /* JADX WARN: Removed duplicated region for block: B:193:0x035c  */
    /* JADX WARN: Removed duplicated region for block: B:197:0x0392  */
    /* JADX WARN: Removed duplicated region for block: B:200:0x03b5  */
    /* JADX WARN: Removed duplicated region for block: B:201:0x03b8  */
    /* JADX WARN: Removed duplicated region for block: B:205:0x03c1  */
    /* JADX WARN: Removed duplicated region for block: B:209:0x03f2  */
    /* JADX WARN: Removed duplicated region for block: B:212:0x0432  */
    /* JADX WARN: Removed duplicated region for block: B:213:0x0435  */
    /* JADX WARN: Removed duplicated region for block: B:217:0x043f  */
    /* JADX WARN: Removed duplicated region for block: B:221:0x0481  */
    /* JADX WARN: Removed duplicated region for block: B:225:0x04b3  */
    /* JADX WARN: Removed duplicated region for block: B:228:0x04d5  */
    /* JADX WARN: Removed duplicated region for block: B:229:0x04d8  */
    /* JADX WARN: Removed duplicated region for block: B:233:0x04e3  */
    /* JADX WARN: Removed duplicated region for block: B:239:0x0509  */
    /* JADX WARN: Removed duplicated region for block: B:243:0x0586  */
    /* JADX WARN: Removed duplicated region for block: B:245:? A[RETURN, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:48:0x0095  */
    /* JADX WARN: Removed duplicated region for block: B:55:0x00a8  */
    /* JADX WARN: Removed duplicated region for block: B:62:0x00bb  */
    /* JADX WARN: Removed duplicated region for block: B:63:0x00c0  */
    /* JADX WARN: Removed duplicated region for block: B:72:0x00d9  */
    /* JADX WARN: Removed duplicated region for block: B:73:0x00de  */
    /* JADX WARN: Removed duplicated region for block: B:82:0x00f7  */
    /* JADX WARN: Removed duplicated region for block: B:90:0x010d  */
    /* JADX WARN: Removed duplicated region for block: B:93:0x0115  */
    /* JADX WARN: Removed duplicated region for block: B:95:0x0120  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void a(final com.quizlet.assembly.compose.modals.x r36, final int r37, final kotlinx.collections.immutable.g r38, final boolean r39, androidx.compose.ui.q r40, final boolean r41, final boolean r42, java.lang.String r43, java.lang.String r44, java.lang.String r45, boolean r46, final kotlin.jvm.functions.c r47, kotlin.jvm.functions.Function0 r48, kotlin.jvm.functions.d r49, androidx.compose.runtime.InterfaceC0806l r50, final int r51, final int r52, final int r53) {
        /*
            Method dump skipped, instructions count: 1447
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_camera.N1.a(com.quizlet.assembly.compose.modals.x, int, kotlinx.collections.immutable.g, boolean, androidx.compose.ui.q, boolean, boolean, java.lang.String, java.lang.String, java.lang.String, boolean, kotlin.jvm.functions.c, kotlin.jvm.functions.Function0, kotlin.jvm.functions.d, androidx.compose.runtime.l, int, int, int):void");
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r6v11 */
    /* JADX WARN: Type inference failed for: r6v12 */
    /* JADX WARN: Type inference failed for: r6v14 */
    /* JADX WARN: Type inference failed for: r6v15 */
    /* JADX WARN: Type inference failed for: r6v33 */
    /* JADX WARN: Type inference failed for: r6v34 */
    public static final void b(final boolean z, final String str, final String str2, final int i, final androidx.compose.ui.text.input.A a, final boolean z2, final boolean z3, boolean z4, final boolean z5, final String str3, final kotlinx.collections.immutable.g gVar, androidx.compose.ui.q qVar, final kotlin.jvm.functions.c cVar, final Function1 function1, final Function1 function12, final Function1 function13, final Function0 function0, InterfaceC0806l interfaceC0806l, final int i2) {
        boolean z6;
        androidx.compose.runtime.B b;
        androidx.compose.runtime.V v;
        int i3;
        boolean z7;
        C0814p c0814p;
        androidx.compose.ui.n nVar;
        C0814p c0814p2;
        final boolean z8;
        C0814p c0814p3;
        final androidx.compose.ui.q qVar2;
        C0814p c0814p4 = (C0814p) interfaceC0806l;
        c0814p4.Z(-2065834368);
        int i4 = i2 | (c0814p4.g(z) ? 4 : 2) | (c0814p4.f(str) ? 32 : 16) | (c0814p4.f(str2) ? 256 : 128) | (c0814p4.d(i) ? 2048 : 1024) | (c0814p4.f(a) ? 16384 : 8192) | (c0814p4.g(z2) ? 131072 : 65536) | (c0814p4.g(z3) ? 1048576 : 524288) | (c0814p4.g(z4) ? 8388608 : 4194304) | (c0814p4.g(z5) ? 67108864 : 33554432) | (c0814p4.f(str3) ? 536870912 : 268435456);
        int i5 = (c0814p4.f(gVar) ? 4 : 2) | 48 | (c0814p4.h(cVar) ? 256 : 128) | (c0814p4.h(function1) ? 2048 : 1024) | (c0814p4.h(function12) ? 16384 : 8192) | (c0814p4.h(function13) ? 131072 : 65536) | (c0814p4.h(function0) ? 1048576 : 524288);
        if ((i4 & 306783379) == 306783378 && (599187 & i5) == 599186 && c0814p4.x()) {
            c0814p4.Q();
            z8 = z4;
            c0814p3 = c0814p4;
            qVar2 = qVar;
        } else {
            androidx.compose.ui.n nVar2 = androidx.compose.ui.n.b;
            androidx.compose.runtime.V v2 = C0804k.a;
            androidx.compose.ui.q qVarG = androidx.compose.ui.platform.N.G(nVar2, "configuration_content_test_tag");
            androidx.compose.runtime.B b2 = com.quizlet.themes.g.a;
            androidx.compose.ui.q qVarF = AbstractC0460p.f(qVarG, ((com.quizlet.themes.b) c0814p4.j(b2)).b.g(), androidx.compose.ui.graphics.F.a);
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            mVar.q();
            float f = com.quizlet.ui.resources.designsystem.generated.j.i;
            mVar.p();
            androidx.compose.ui.q qVarV = AbstractC0382e.v(qVarF, f, com.quizlet.ui.resources.designsystem.generated.j.j);
            C0380d c0380d = AbstractC0398m.a;
            mVar.s();
            float f2 = com.quizlet.ui.resources.designsystem.generated.j.h;
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.g(f2), androidx.compose.ui.b.m, c0814p4, 0);
            int i6 = c0814p4.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p4.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p4, qVarV);
            InterfaceC0915k.D0.getClass();
            C0913i c0913i = C0914j.b;
            c0814p4.b0();
            if (c0814p4.O) {
                c0814p4.k(c0913i);
            } else {
                c0814p4.l0();
            }
            C0776c.E(c0814p4, bA, C0914j.f);
            C0776c.E(c0814p4, interfaceC0803j0L, C0914j.e);
            C0912h c0912h = C0914j.g;
            if (c0814p4.O || !Intrinsics.b(c0814p4.I(), Integer.valueOf(i6))) {
                android.support.v4.media.session.a.z(i6, c0814p4, i6, c0912h);
            }
            C0776c.E(c0814p4, qVarC, C0914j.d);
            c0814p4.X(181814809);
            if (str == null) {
                z7 = z3;
                b = b2;
                i3 = i5;
                c0814p = c0814p4;
                v = v2;
                z6 = false;
            } else {
                z6 = false;
                b = b2;
                v = v2;
                i3 = i5;
                z7 = z3;
                Q4.b(str, null, ((com.quizlet.themes.b) c0814p4.j(b2)).b.e(), 0L, null, 0L, null, 0L, 0, false, 0, 0, null, ((com.quizlet.themes.f) c0814p4.j(com.quizlet.themes.w.a)).e, c0814p4, (i4 >> 3) & 14, 0, 65530);
                c0814p = c0814p4;
                Unit unit = Unit.a;
            }
            c0814p.p(z6);
            c0814p.X(181822166);
            if (str2 == null) {
                nVar = nVar2;
                c0814p2 = c0814p;
            } else {
                String strC = AbstractC3106b5.c(R.string.practice_test_configuration_modal_subheader, new Object[]{str2}, c0814p);
                long jE = ((com.quizlet.themes.b) c0814p.j(b)).b.e();
                androidx.compose.ui.text.L l = ((com.quizlet.themes.f) c0814p.j(com.quizlet.themes.w.a)).o;
                mVar.s();
                C0814p c0814p5 = c0814p;
                nVar = nVar2;
                Q4.b(strC, AbstractC0382e.y(nVar2, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, f2, 7), jE, 0L, null, 0L, null, 0L, 0, false, 0, 0, null, l, c0814p5, 0, 0, 65528);
                c0814p2 = c0814p5;
                Unit unit2 = Unit.a;
            }
            c0814p2.p(z6);
            c0814p2.X(181840448);
            boolean z9 = (i4 & 3670016) == 1048576 ? true : z6;
            Object objI = c0814p2.I();
            androidx.compose.runtime.V v3 = v;
            if (z9 || objI == v3) {
                objI = new C1483i(z7, 17);
                c0814p2.i0(objI);
            }
            c0814p2.p(z6);
            int i7 = i4 >> 6;
            int i8 = i3;
            C0814p c0814p6 = c0814p2;
            d(a, i, (Function0) objI, function1, c0814p6, ((i4 >> 12) & 14) | (i7 & ContentType.LONG_FORM_ON_DEMAND) | (i8 & 7168));
            Integer num = (Integer) gVar.get(EnumC4533y0.MCQ_WITH_SINGLE_ANSWER);
            int i9 = i8 >> 3;
            e(AbstractC3106b5.d(c0814p6, R.string.practice_test_mcq_toggle), z4, (num != null ? num.intValue() : z6) > 0 ? true : z6, function12, "mcq_switch_test_tag", c0814p6, ((i4 >> 18) & ContentType.LONG_FORM_ON_DEMAND) | 24576 | (i9 & 7168));
            Integer num2 = (Integer) gVar.get(EnumC4533y0.QUESTION_WITH_SHORT_FREE_RESPONSE);
            z8 = z4;
            e(AbstractC3106b5.d(c0814p6, R.string.practice_test_written_toggle), z5, (num2 != null ? num2.intValue() : z6) > 0 ? true : z6, function13, "written_switch_test_tag", c0814p6, ((i4 >> 21) & ContentType.LONG_FORM_ON_DEMAND) | 24576 | ((i8 >> 6) & 7168));
            androidx.compose.ui.n nVar3 = nVar;
            androidx.compose.ui.q qVarC2 = androidx.compose.foundation.layout.K0.c(nVar3, 1.0f);
            mVar.q();
            androidx.compose.ui.q qVarG2 = androidx.compose.ui.platform.N.G(AbstractC0382e.y(qVarC2, DefinitionKt.NO_Float_VALUE, f, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), "take_test_configuration_modal_button");
            c0814p6.X(181882293);
            boolean z10 = ((i8 & 896) == 256 ? true : z6) | ((i4 & 57344) == 16384 ? true : z6) | ((i4 & 29360128) == 8388608 ? true : z6) | ((i4 & 234881024) == 67108864 ? true : z6);
            Object objI2 = c0814p6.I();
            if (z10 || objI2 == v3) {
                objI2 = new Function0() { // from class: com.quizlet.features.practicetest.common.composables.c
                    @Override // kotlin.jvm.functions.Function0
                    public final Object invoke() {
                        cVar.invoke(Integer.valueOf(Integer.parseInt(a.a.a)), Boolean.valueOf(z8), Boolean.valueOf(z5));
                        return Unit.a;
                    }
                };
                c0814p6.i0(objI2);
            }
            c0814p6.p(z6);
            W4.a(str3, qVarG2, (Function0) objI2, z2, null, null, null, null, null, false, c0814p6, ((i4 >> 27) & 14) | (i7 & 7168), 1008);
            c0814p3 = c0814p6;
            c0814p3.X(181889523);
            if (z) {
                androidx.compose.ui.q qVarC3 = androidx.compose.foundation.layout.K0.c(nVar3, 1.0f);
                mVar.n();
                AbstractC3777z5.a(AbstractC3106b5.d(c0814p3, R.string.practice_test_see_question_bank_button), qVarC3, null, AbstractC0382e.c(DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.o, 1), null, function0, c0814p3, (i9 & 458752) | 48, 20);
                c0814p3 = c0814p3;
            }
            c0814p3.p(false);
            c0814p3.p(true);
            qVar2 = nVar3;
        }
        C0813o0 c0813o0R = c0814p3.r();
        if (c0813o0R != null) {
            final boolean z11 = z8;
            c0813o0R.d = new Function2(z, str, str2, i, a, z2, z3, z11, z5, str3, gVar, qVar2, cVar, function1, function12, function13, function0, i2) { // from class: com.quizlet.features.practicetest.common.composables.d
                public final /* synthetic */ boolean a;
                public final /* synthetic */ String b;
                public final /* synthetic */ String c;
                public final /* synthetic */ int d;
                public final /* synthetic */ A e;
                public final /* synthetic */ boolean f;
                public final /* synthetic */ boolean g;
                public final /* synthetic */ boolean h;
                public final /* synthetic */ boolean i;
                public final /* synthetic */ String j;
                public final /* synthetic */ kotlinx.collections.immutable.g k;
                public final /* synthetic */ q l;
                public final /* synthetic */ kotlin.jvm.functions.c m;
                public final /* synthetic */ Function1 n;
                public final /* synthetic */ Function1 o;
                public final /* synthetic */ Function1 p;
                public final /* synthetic */ Function0 q;

                @Override // kotlin.jvm.functions.Function2
                public final Object invoke(Object obj, Object obj2) {
                    ((Integer) obj2).getClass();
                    int iH = C0776c.H(1);
                    Function1 function14 = this.p;
                    Function0 function02 = this.q;
                    N1.b(this.a, this.b, this.c, this.d, this.e, this.f, this.g, this.h, this.i, this.j, this.k, this.l, this.m, this.n, this.o, function14, function02, (InterfaceC0806l) obj, iH);
                    return Unit.a;
                }
            };
        }
    }

    public static final void c(androidx.compose.ui.text.input.A a, Function0 function0, Function1 function1, InterfaceC0806l interfaceC0806l, int i) {
        androidx.compose.ui.text.input.A a2;
        int i2;
        Function0 function02;
        C0814p c0814p;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-1684189873);
        if ((i & 6) == 0) {
            a2 = a;
            i2 = (c0814p2.f(a2) ? 4 : 2) | i;
        } else {
            a2 = a;
            i2 = i;
        }
        if ((i & 48) == 0) {
            function02 = function0;
            i2 |= c0814p2.h(function02) ? 32 : 16;
        } else {
            function02 = function0;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p2.h(function1) ? 256 : 128;
        }
        if ((i2 & 147) == 146 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            androidx.compose.ui.q qVarF = androidx.compose.foundation.layout.K0.f(androidx.compose.foundation.layout.K0.q(nVar, DefinitionKt.NO_Float_VALUE, com.quizlet.themes.m.S0, 1), DefinitionKt.NO_Float_VALUE, com.quizlet.themes.m.T0, 1);
            boolean zBooleanValue = ((Boolean) function02.invoke()).booleanValue();
            C0490g0 c0490g0 = new C0490g0(8, 0, ContentType.USER_GENERATED_LIVE);
            androidx.compose.ui.text.L lB = androidx.compose.ui.text.L.b(((com.quizlet.themes.f) c0814p2.j(com.quizlet.themes.w.a)).j, 0L, 0L, null, null, 0L, 3, 0L, null, 16744447);
            mVar.d();
            androidx.compose.foundation.shape.d dVarA = androidx.compose.foundation.shape.e.a(com.quizlet.ui.resources.designsystem.generated.f.g);
            A4 a4K = AbstractC3745v5.k(com.quizlet.assembly.compose.input.n.a, c0814p2, 0);
            long j = C0861v.f;
            c0814p = c0814p2;
            K4.a(a2, function1, qVarF, false, lB, null, null, null, null, null, zBooleanValue, null, c0490g0, null, true, 0, 0, dVarA, a4K.a(a4K.a, a4K.b, a4K.c, a4K.d, a4K.e, a4K.f, a4K.g, a4K.h, a4K.i, a4K.j, a4K.k, ((-14337) & 2048) != 0 ? a4K.l : j, ((-14337) & 4096) != 0 ? a4K.m : j, ((-14337) & 8192) != 0 ? a4K.n : j, a4K.o, a4K.p, a4K.q, a4K.r, a4K.s, a4K.t, a4K.u, a4K.v, ((-14337) & 4194304) != 0 ? a4K.w : 0L, a4K.x, a4K.y, a4K.z, a4K.A, a4K.B, a4K.C, a4K.D, a4K.E, a4K.F, a4K.G, a4K.H, a4K.I, a4K.J, a4K.K, a4K.L, a4K.M, a4K.N, a4K.O, a4K.P, a4K.Q), c0814p, (i2 & 14) | ((i2 >> 3) & ContentType.LONG_FORM_ON_DEMAND), 12779520, 1925080);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new androidx.navigation.compose.u(i, 25, a, function0, function1);
        }
    }

    public static final void d(androidx.compose.ui.text.input.A a, int i, Function0 function0, Function1 function1, InterfaceC0806l interfaceC0806l, int i2) {
        int i3;
        long jE;
        long jF;
        C0814p c0814p;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-1179472240);
        if ((i2 & 6) == 0) {
            i3 = (c0814p2.f(a) ? 4 : 2) | i2;
        } else {
            i3 = i2;
        }
        if ((i2 & 48) == 0) {
            i3 |= c0814p2.d(i) ? 32 : 16;
        }
        if ((i2 & 384) == 0) {
            i3 |= c0814p2.h(function0) ? 256 : 128;
        }
        if ((i2 & 3072) == 0) {
            i3 |= c0814p2.h(function1) ? 2048 : 1024;
        }
        if ((i3 & 1171) == 1170 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            androidx.compose.ui.q qVarC = androidx.compose.foundation.layout.K0.c(nVar, 1.0f);
            androidx.compose.foundation.layout.G0 g0B = androidx.compose.foundation.layout.E0.b(AbstractC0398m.a, androidx.compose.ui.b.k, c0814p2, 48);
            int i4 = c0814p2.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p2.l();
            androidx.compose.ui.q qVarC2 = androidx.compose.ui.a.c(c0814p2, qVarC);
            InterfaceC0915k.D0.getClass();
            C0913i c0913i = C0914j.b;
            c0814p2.b0();
            if (c0814p2.O) {
                c0814p2.k(c0913i);
            } else {
                c0814p2.l0();
            }
            C0776c.E(c0814p2, g0B, C0914j.f);
            C0776c.E(c0814p2, interfaceC0803j0L, C0914j.e);
            C0912h c0912h = C0914j.g;
            if (c0814p2.O || !Intrinsics.b(c0814p2.I(), Integer.valueOf(i4))) {
                android.support.v4.media.session.a.z(i4, c0814p2, i4, c0912h);
            }
            C0776c.E(c0814p2, qVarC2, C0914j.d);
            String strD = AbstractC3106b5.d(c0814p2, R.string.practice_test_question_count);
            if (((Boolean) function0.invoke()).booleanValue()) {
                c0814p2.X(-1998350121);
                jE = ((com.quizlet.themes.b) c0814p2.j(com.quizlet.themes.g.a)).b.a();
                c0814p2.p(false);
            } else {
                c0814p2.X(-1998278511);
                jE = ((com.quizlet.themes.b) c0814p2.j(com.quizlet.themes.g.a)).b.e();
                c0814p2.p(false);
            }
            androidx.compose.runtime.B b = com.quizlet.themes.w.a;
            Q4.b(strD, null, jE, 0L, null, 0L, null, 0L, 0, false, 0, 0, null, ((com.quizlet.themes.f) c0814p2.j(b)).j, c0814p2, 0, 0, 65530);
            com.quizlet.themes.m.g.w();
            androidx.compose.ui.q qVarY = AbstractC0382e.y(nVar, com.quizlet.ui.resources.designsystem.generated.j.f, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 14);
            String strC = AbstractC3106b5.c(R.string.practice_test_question_count_max, new Object[]{Integer.valueOf(i)}, c0814p2);
            androidx.compose.ui.text.L l = ((com.quizlet.themes.f) c0814p2.j(b)).o;
            if (((Boolean) function0.invoke()).booleanValue()) {
                c0814p2.X(-1997830313);
                jF = ((com.quizlet.themes.b) c0814p2.j(com.quizlet.themes.g.a)).b.a();
                c0814p2.p(false);
            } else {
                c0814p2.X(-1997758641);
                jF = ((com.quizlet.themes.b) c0814p2.j(com.quizlet.themes.g.a)).b.f();
                c0814p2.p(false);
            }
            Q4.b(strC, qVarY, jF, 0L, null, 0L, null, 0L, 2, false, 1, 0, null, l, c0814p2, 0, 3120, 55288);
            c0814p = c0814p2;
            if (1.0f <= 0.0d) {
                throw new IllegalArgumentException(android.support.v4.media.session.a.i("invalid weight ", 1.0f, "; must be greater than zero").toString());
            }
            AbstractC0382e.f(c0814p, new LayoutWeightElement(1.0f <= Float.MAX_VALUE ? 1.0f : Float.MAX_VALUE, true));
            int i5 = i3 & 14;
            int i6 = i3 >> 3;
            c(a, function0, function1, c0814p, i5 | (i6 & ContentType.LONG_FORM_ON_DEMAND) | (i6 & 896));
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C4218e(a, i, function0, function1, i2);
        }
    }

    public static final void e(String str, boolean z, boolean z2, Function1 function1, String str2, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        long jB;
        boolean z3;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-680108188);
        if ((i & 6) == 0) {
            i2 = (c0814p.f(str) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.g(z) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p.g(z2) ? 256 : 128;
        }
        if ((i & 3072) == 0) {
            i2 |= c0814p.h(function1) ? 2048 : 1024;
        }
        if ((i & 24576) == 0) {
            i2 |= c0814p.f(str2) ? 16384 : 8192;
        }
        int i3 = i2;
        if ((i3 & 9363) == 9362 && c0814p.x()) {
            c0814p.Q();
        } else {
            Object[] objArr = new Object[0];
            c0814p.X(-2004974072);
            boolean z4 = (i3 & ContentType.LONG_FORM_ON_DEMAND) == 32;
            Object objI = c0814p.I();
            androidx.compose.runtime.V v = C0804k.a;
            if (z4 || objI == v) {
                objI = new C1483i(z, 18);
                c0814p.i0(objI);
            }
            c0814p.p(false);
            InterfaceC0773a0 interfaceC0773a0 = (InterfaceC0773a0) L4.d(objArr, null, (Function0) objI, c0814p, 0, 6);
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            androidx.compose.ui.q qVarC = androidx.compose.foundation.layout.K0.c(nVar, 1.0f);
            androidx.compose.foundation.layout.G0 g0B = androidx.compose.foundation.layout.E0.b(AbstractC0398m.g, androidx.compose.ui.b.k, c0814p, 54);
            int i4 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC2 = androidx.compose.ui.a.c(c0814p, qVarC);
            InterfaceC0915k.D0.getClass();
            C0913i c0913i = C0914j.b;
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0776c.E(c0814p, g0B, C0914j.f);
            C0776c.E(c0814p, interfaceC0803j0L, C0914j.e);
            C0912h c0912h = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i4))) {
                android.support.v4.media.session.a.z(i4, c0814p, i4, c0912h);
            }
            C0776c.E(c0814p, qVarC2, C0914j.d);
            if (1.0f <= 0.0d) {
                throw new IllegalArgumentException(android.support.v4.media.session.a.i("invalid weight ", 1.0f, "; must be greater than zero").toString());
            }
            LayoutWeightElement layoutWeightElement = new LayoutWeightElement(1.0f > Float.MAX_VALUE ? Float.MAX_VALUE : 1.0f, true);
            if (z2) {
                c0814p.X(-1678526896);
                jB = ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).b.e();
                c0814p.p(false);
                z3 = false;
            } else {
                c0814p.X(-1678449613);
                jB = ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).b.b();
                z3 = false;
                c0814p.p(false);
            }
            Q4.b(str, layoutWeightElement, jB, 0L, null, 0L, null, 0L, 0, false, 0, 0, null, ((com.quizlet.themes.f) c0814p.j(com.quizlet.themes.w.a)).j, c0814p, i3 & 14, 0, 65528);
            boolean zBooleanValue = ((Boolean) interfaceC0773a0.getValue()).booleanValue();
            androidx.compose.ui.q qVarG = androidx.compose.ui.platform.N.G(nVar, str2);
            c0814p.X(-1162514497);
            boolean zF = c0814p.f(interfaceC0773a0) | ((i3 & 7168) == 2048 ? true : z3);
            Object objI2 = c0814p.I();
            if (zF || objI2 == v) {
                objI2 = new com.quizlet.features.flashcards.settings.ui.e(7, interfaceC0773a0, function1);
                c0814p.i0(objI2);
            }
            c0814p.p(z3);
            c0814p = c0814p;
            S4.a(zBooleanValue, qVarG, (Function1) objI2, z2, c0814p, (i3 << 3) & 7168, 0);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.tabs.c(str, z, z2, function1, str2, i);
        }
    }

    public static final String f(int i, byte[] bArr, int i2) {
        int i3;
        int i4;
        int i5;
        int i6;
        int i7;
        int i8;
        int i9;
        int i10;
        int i11 = i;
        int i12 = 2;
        Intrinsics.checkNotNullParameter(bArr, "<this>");
        if (i11 < 0 || i2 > bArr.length || i11 > i2) {
            throw new IndexOutOfBoundsException("size=" + bArr.length + " beginIndex=" + i11 + " endIndex=" + i2);
        }
        char[] cArr = new char[i2 - i11];
        int i13 = 0;
        while (i11 < i2) {
            byte b = bArr[i11];
            if (b >= 0) {
                i9 = i13 + 1;
                cArr[i13] = (char) b;
                i11++;
                while (i11 < i2) {
                    byte b2 = bArr[i11];
                    if (b2 < 0) {
                        break;
                    }
                    i11++;
                    cArr[i9] = (char) b2;
                    i9++;
                }
                Unit unit = Unit.a;
            } else if ((b >> 5) == -2) {
                int i14 = i11 + 1;
                if (i2 <= i14) {
                    i9 = i13 + 1;
                    cArr[i13] = (char) 65533;
                } else {
                    byte b3 = bArr[i14];
                    if ((b3 & 192) == 128) {
                        int i15 = (b << 6) ^ (b3 ^ 3968);
                        if (i15 < 128) {
                            i9 = i13 + 1;
                            cArr[i13] = (char) 65533;
                        } else {
                            i9 = i13 + 1;
                            cArr[i13] = (char) i15;
                        }
                        Unit unit2 = Unit.a;
                        i10 = i12;
                        i11 += i10;
                    } else {
                        i9 = i13 + 1;
                        cArr[i13] = (char) 65533;
                    }
                }
                Unit unit3 = Unit.a;
                i10 = 1;
                i11 += i10;
            } else {
                if ((b >> 4) == -2) {
                    int i16 = i11 + 2;
                    if (i2 <= i16) {
                        i6 = i13 + 1;
                        cArr[i13] = (char) 65533;
                        Unit unit4 = Unit.a;
                        int i17 = i11 + 1;
                        i7 = (i2 <= i17 || (bArr[i17] & 192) != 128) ? 1 : i12;
                    } else {
                        byte b4 = bArr[i11 + 1];
                        if ((b4 & 192) == 128) {
                            byte b5 = bArr[i16];
                            if ((b5 & 192) == 128) {
                                int i18 = ((b5 ^ (-123008)) ^ (b4 << 6)) ^ (b << 12);
                                if (i18 < 2048) {
                                    i8 = i13 + 1;
                                    cArr[i13] = (char) 65533;
                                } else if (55296 > i18 || i18 >= 57344) {
                                    char c = (char) i18;
                                    i8 = i13 + 1;
                                    cArr[i13] = c;
                                } else {
                                    i8 = i13 + 1;
                                    cArr[i13] = (char) 65533;
                                }
                                Unit unit5 = Unit.a;
                                i6 = i8;
                                i7 = 3;
                            } else {
                                i6 = i13 + 1;
                                cArr[i13] = (char) 65533;
                                Unit unit6 = Unit.a;
                                i7 = i12;
                            }
                        } else {
                            i6 = i13 + 1;
                            cArr[i13] = (char) 65533;
                            Unit unit7 = Unit.a;
                            i7 = 1;
                        }
                    }
                    i11 += i7;
                    i3 = i12;
                    i13 = i6;
                } else {
                    if ((b >> 3) == -2) {
                        int i19 = i11 + 3;
                        if (i2 <= i19) {
                            i4 = i13 + 1;
                            cArr[i13] = 65533;
                            Unit unit8 = Unit.a;
                            int i20 = i11 + 1;
                            if (i2 <= i20 || (bArr[i20] & 192) != 128) {
                                i3 = i12;
                                i12 = 1;
                                i11 += i12;
                            } else {
                                int i21 = i11 + 2;
                                if (i2 <= i21 || (bArr[i21] & 192) != 128) {
                                    i3 = i12;
                                    i11 += i12;
                                } else {
                                    i3 = i12;
                                    i12 = 3;
                                    i11 += i12;
                                }
                            }
                        } else {
                            byte b6 = bArr[i11 + 1];
                            if ((b6 & 192) == 128) {
                                byte b7 = bArr[i11 + 2];
                                i3 = i12;
                                if ((b7 & 192) == 128) {
                                    byte b8 = bArr[i19];
                                    if ((b8 & 192) == 128) {
                                        int i22 = (((b8 ^ 3678080) ^ (b7 << 6)) ^ (b6 << 12)) ^ (b << 18);
                                        if (i22 > 1114111) {
                                            i4 = i13 + 1;
                                            cArr[i13] = 65533;
                                        } else if ((55296 > i22 || i22 >= 57344) && i22 >= 65536) {
                                            if (i22 != 65533) {
                                                cArr[i13] = (char) ((i22 >>> 10) + 55232);
                                                i5 = i13 + 2;
                                                cArr[i13 + 1] = (char) ((i22 & 1023) + 56320);
                                            } else {
                                                cArr[i13] = 65533;
                                                i5 = i13 + 1;
                                            }
                                            Unit unit9 = Unit.a;
                                            i4 = i5;
                                            i12 = 4;
                                        } else {
                                            i4 = i13 + 1;
                                            cArr[i13] = 65533;
                                        }
                                        Unit unit10 = Unit.a;
                                        i12 = 4;
                                    } else {
                                        i4 = i13 + 1;
                                        cArr[i13] = 65533;
                                        Unit unit11 = Unit.a;
                                        i12 = 3;
                                    }
                                } else {
                                    i4 = i13 + 1;
                                    cArr[i13] = 65533;
                                    Unit unit12 = Unit.a;
                                    i12 = i3;
                                }
                                i11 += i12;
                            } else {
                                i3 = i12;
                                i4 = i13 + 1;
                                cArr[i13] = 65533;
                                Unit unit13 = Unit.a;
                                i12 = 1;
                                i11 += i12;
                            }
                        }
                    } else {
                        i3 = i12;
                        i4 = i13 + 1;
                        cArr[i13] = 65533;
                        i11++;
                    }
                    i13 = i4;
                }
                i12 = i3;
            }
            i3 = i12;
            i13 = i9;
            i12 = i3;
        }
        return kotlin.text.D.h(cArr, 0, i13);
    }

    public static final void g(androidx.navigation.E e, String str, List list, List list2, androidx.compose.runtime.internal.d dVar) {
        C1275h destination = new C1275h((C1276i) e.g.b(C1276i.class), new androidx.compose.runtime.internal.d(true, -1516831465, new androidx.navigation.compose.v(dVar, 0)));
        destination.j(str);
        Iterator it2 = list.iterator();
        while (it2.hasNext()) {
            C1287i c1287i = (C1287i) it2.next();
            String argumentName = c1287i.a;
            C1289k argument = c1287i.b;
            Intrinsics.checkNotNullParameter(argumentName, "argumentName");
            Intrinsics.checkNotNullParameter(argument, "argument");
            androidx.navigation.internal.m mVar = destination.b;
            mVar.getClass();
            Intrinsics.checkNotNullParameter(argumentName, "argumentName");
            Intrinsics.checkNotNullParameter(argument, "argument");
            ((LinkedHashMap) mVar.e).put(argumentName, argument);
        }
        Iterator it3 = list2.iterator();
        while (it3.hasNext()) {
            destination.a((C1301x) it3.next());
        }
        Intrinsics.checkNotNullParameter(destination, "destination");
        e.j.add(destination);
    }

    public static final void h(androidx.navigation.E e, C4950i c4950i, kotlin.collections.L l, kotlin.collections.K k, androidx.compose.runtime.internal.d dVar) {
        androidx.compose.material.navigation.j navDestination = new androidx.compose.material.navigation.j((C1276i) e.g.b(C1276i.class), c4950i, l, dVar);
        k.getClass();
        kotlin.collections.J.a.getClass();
        Intrinsics.checkNotNullParameter(navDestination, "navDestination");
        e.j.add(navDestination.a());
    }

    public static void i(androidx.navigation.E e, String str, androidx.compose.runtime.internal.d dVar) {
        kotlin.collections.K k = kotlin.collections.K.a;
        g(e, str, k, k, dVar);
    }
}

package com.google.android.gms.internal.mlkit_vision_document_scanner;

import android.content.Context;
import androidx.compose.foundation.AbstractC0460p;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.foundation.layout.C0380d;
import androidx.compose.foundation.layout.C0384f;
import androidx.compose.foundation.layout.C0386g;
import androidx.compose.foundation.layout.C0416v0;
import androidx.compose.material3.AbstractC0725t3;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import androidx.compose.ui.platform.AndroidCompositionLocals_androidKt;
import androidx.compose.ui.q;
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3274u5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.E6;
import com.quizlet.features.achievements.ui.composables.C4214a;
import com.quizlet.features.folders.composables.C4256l;
import com.quizlet.learn.settings.data.WrittenQuestionGradingOption;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.ui.studymodes.assistant.settings.data.LearnSettingsUpdateData;
import com.quizlet.quizletandroid.ui.studymodes.assistant.settings.data.m;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.WeakHashMap;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class E6 {
    public static final void c(boolean z, boolean z2, boolean z3, Function1 function1, Function1 function12, Function1 function13, String str, String str2, boolean z4, androidx.compose.ui.q qVar, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-574999733);
        if ((i & 6) == 0) {
            i2 = (c0814p.g(z) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.g(z2) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p.g(z3) ? 256 : 128;
        }
        if ((i & 3072) == 0) {
            i2 |= c0814p.h(function1) ? 2048 : 1024;
        }
        if ((i & 24576) == 0) {
            i2 |= c0814p.h(function12) ? 16384 : 8192;
        }
        if ((196608 & i) == 0) {
            i2 |= c0814p.h(function13) ? 131072 : 65536;
        }
        if ((1572864 & i) == 0) {
            i2 |= c0814p.f(str) ? 1048576 : 524288;
        }
        if ((12582912 & i) == 0) {
            i2 |= c0814p.f(str2) ? 8388608 : 4194304;
        }
        if ((100663296 & i) == 0) {
            i2 |= c0814p.g(z4) ? 67108864 : 33554432;
        }
        if ((805306368 & i) == 0) {
            i2 |= c0814p.f(qVar) ? 536870912 : 268435456;
        }
        int i3 = i2;
        if ((i3 & 306783379) == 306783378 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.ui.q qVarP = p(c0814p, qVar);
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.c, androidx.compose.ui.b.m, c0814p, 0);
            int i4 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, qVarP);
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
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i4))) {
                android.support.v4.media.session.a.z(i4, c0814p, i4, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            m(AbstractC3106b5.d(c0814p, R.string.learn_settings_answer_with_title), c0814p, 0);
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            com.quizlet.themes.m.g.u();
            int i5 = i3 >> 3;
            n(str, z, function1, "answerWithTermTag", AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.g, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), c0814p, ((i3 >> 18) & 14) | 3072 | ((i3 << 3) & ContentType.LONG_FORM_ON_DEMAND) | (i5 & 896), 0);
            c0814p.X(95020823);
            if (!z4) {
                n(str2, z2, function12, "answerWithDefinitionTag", null, c0814p, ((i3 >> 21) & 14) | 3072 | (i3 & ContentType.LONG_FORM_ON_DEMAND) | ((i3 >> 6) & 896), 16);
            }
            c0814p.p(false);
            c0814p.X(95030725);
            if (z4) {
                n(AbstractC3106b5.d(c0814p, R.string.assistant_settings_start_with_location), z3, function13, "answerWithLocationTag", null, c0814p, (i5 & ContentType.LONG_FORM_ON_DEMAND) | 3072 | ((i3 >> 9) & 896), 16);
            }
            c0814p.p(false);
            androidx.compose.animation.E.f((z || z2 || z3) ? false : true, null, null, null, null, com.quizlet.quizletandroid.ui.studymodes.assistant.settings.composables.c.b, c0814p, 1572870, 30);
            c0814p = c0814p;
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.quizletandroid.ui.studymodes.assistant.settings.n(z, z2, z3, function1, function12, function13, str, str2, z4, qVar, i, 1);
        }
    }

    public static final void d(final com.quizlet.quizletandroid.ui.studymodes.assistant.settings.data.m mVar, final LearnSettingsUpdateData learnSettingsUpdateData, final Function1 function1, final Function1 function12, final Function1 function13, final Function1 function14, final Function1 function15, final Function1 function16, final Function1 function17, final Function1 function18, final Function1 function19, final Function1 function110, final Function0 function0, final Function0 function02, final Function0 function03, final androidx.compose.ui.q qVar, InterfaceC0806l interfaceC0806l, final int i) {
        boolean z;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(256096267);
        int i2 = i | (c0814p.h(mVar) ? 4 : 2) | (c0814p.f(learnSettingsUpdateData) ? 32 : 16) | (c0814p.h(function1) ? 256 : 128) | (c0814p.h(function12) ? 2048 : 1024) | (c0814p.h(function13) ? 16384 : 8192) | (c0814p.h(function14) ? 131072 : 65536) | (c0814p.h(function15) ? 1048576 : 524288) | (c0814p.h(function16) ? 8388608 : 4194304) | (c0814p.h(function17) ? 67108864 : 33554432) | (c0814p.h(function18) ? 536870912 : 268435456);
        int i3 = (c0814p.h(function19) ? 4 : 2) | (c0814p.h(function110) ? 32 : 16) | (c0814p.h(function0) ? 256 : 128) | (c0814p.h(function02) ? 2048 : 1024) | (c0814p.h(function03) ? 16384 : 8192) | (c0814p.f(qVar) ? 131072 : 65536);
        if ((i2 & 306783379) == 306783378 && (i3 & 74899) == 74898 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.ui.q qVarU = AbstractC0460p.u(qVar, AbstractC0460p.r(c0814p), false, 14);
            com.quizlet.themes.m mVar2 = com.quizlet.themes.m.g;
            mVar2.s();
            float f = com.quizlet.ui.resources.designsystem.generated.j.h;
            androidx.compose.ui.q qVarU2 = AbstractC0382e.u(qVarU, f);
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.c, androidx.compose.ui.b.m, c0814p, 0);
            int i4 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, qVarU2);
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
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i4))) {
                android.support.v4.media.session.a.z(i4, c0814p, i4, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            f(learnSettingsUpdateData.a, learnSettingsUpdateData.b, function1, function12, null, c0814p, i2 & 8064);
            com.quizlet.qutils.string.g gVarF = AbstractC3274u5.f(mVar.n);
            androidx.compose.runtime.X0 x0 = AndroidCompositionLocals_androidKt.b;
            String strA = gVarF.a((Context) c0814p.j(x0));
            String strA2 = AbstractC3274u5.f(mVar.o).a((Context) c0814p.j(x0));
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            mVar2.s();
            c(learnSettingsUpdateData.d, learnSettingsUpdateData.e, learnSettingsUpdateData.f, function14, function15, function16, strA, strA2, mVar.p, AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, f, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), c0814p, (i2 >> 6) & 523264);
            mVar2.s();
            int i5 = i3 >> 9;
            int i6 = i2 >> 9;
            l(mVar.k, function03, learnSettingsUpdateData.g, learnSettingsUpdateData.h, learnSettingsUpdateData.i, function17, function18, function19, AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, f, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), c0814p, (i5 & ContentType.LONG_FORM_ON_DEMAND) | (458752 & i6) | (i6 & 3670016) | ((i3 << 21) & 29360128));
            mVar2.s();
            g(mVar.a, learnSettingsUpdateData.l, learnSettingsUpdateData.c, function110, function13, AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, f, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), c0814p, ((i3 << 6) & 7168) | (57344 & i2));
            c0814p = c0814p;
            c0814p.X(1024762707);
            if (mVar.q) {
                androidx.compose.ui.q qVarC2 = androidx.compose.foundation.layout.K0.c(nVar, 1.0f);
                mVar2.s();
                androidx.compose.ui.q qVarP = p(c0814p, AbstractC0382e.y(qVarC2, DefinitionKt.NO_Float_VALUE, f, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13));
                c0814p.X(1024771114);
                boolean z2 = (i3 & 896) == 256;
                Object objI = c0814p.I();
                if (z2 || objI == C0804k.a) {
                    objI = new com.quizlet.features.setpage.composable.a(18, function0);
                    c0814p.i0(objI);
                }
                z = false;
                c0814p.p(false);
                o(AbstractC0460p.l(qVarP, false, null, (Function0) objI, 7), c0814p, 0);
            } else {
                z = false;
            }
            c0814p.p(z);
            mVar2.s();
            k(i5 & 14, c0814p, AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, f, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), function02);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new Function2(learnSettingsUpdateData, function1, function12, function13, function14, function15, function16, function17, function18, function19, function110, function0, function02, function03, qVar, i) { // from class: com.quizlet.quizletandroid.ui.studymodes.assistant.settings.composables.d
                public final /* synthetic */ LearnSettingsUpdateData b;
                public final /* synthetic */ Function1 c;
                public final /* synthetic */ Function1 d;
                public final /* synthetic */ Function1 e;
                public final /* synthetic */ Function1 f;
                public final /* synthetic */ Function1 g;
                public final /* synthetic */ Function1 h;
                public final /* synthetic */ Function1 i;
                public final /* synthetic */ Function1 j;
                public final /* synthetic */ Function1 k;
                public final /* synthetic */ Function1 l;
                public final /* synthetic */ Function0 m;
                public final /* synthetic */ Function0 n;
                public final /* synthetic */ Function0 o;
                public final /* synthetic */ q p;

                @Override // kotlin.jvm.functions.Function2
                public final Object invoke(Object obj, Object obj2) {
                    ((Integer) obj2).getClass();
                    int iH = C0776c.H(1);
                    m mVar3 = this.a;
                    Function0 function04 = this.o;
                    q qVar2 = this.p;
                    E6.d(mVar3, this.b, this.c, this.d, this.e, this.f, this.g, this.h, this.i, this.j, this.k, this.l, this.m, this.n, function04, qVar2, (InterfaceC0806l) obj, iH);
                    return Unit.a;
                }
            };
        }
    }

    public static final void e(String str, androidx.compose.ui.q qVar, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(1965123559);
        int i2 = i | (c0814p2.f(str) ? 4 : 2) | (c0814p2.f(qVar) ? 32 : 16);
        if ((i2 & 19) == 18 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            c0814p = c0814p2;
            androidx.compose.material3.Q4.b(str, qVar, ((com.quizlet.themes.b) c0814p2.j(com.quizlet.themes.g.a)).b.a(), 0L, null, 0L, null, 0L, 0, false, 0, 0, null, ((com.quizlet.themes.f) c0814p2.j(com.quizlet.themes.w.a)).k, c0814p, i2 & 126, 0, 65528);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C4214a(str, qVar, i, 10);
        }
    }

    public static final void f(boolean z, boolean z2, Function1 function1, Function1 function12, androidx.compose.ui.n nVar, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        boolean z3;
        androidx.compose.ui.n nVar2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1305366286);
        if ((i & 6) == 0) {
            i2 = (c0814p.g(z) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            z3 = z2;
            i2 |= c0814p.g(z3) ? 32 : 16;
        } else {
            z3 = z2;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p.h(function1) ? 256 : 128;
        }
        if ((i & 3072) == 0) {
            i2 |= c0814p.h(function12) ? 2048 : 1024;
        }
        int i3 = i2 | 24576;
        if ((i3 & 9363) == 9362 && c0814p.x()) {
            c0814p.Q();
            nVar2 = nVar;
        } else {
            androidx.compose.ui.n nVar3 = androidx.compose.ui.n.b;
            androidx.compose.ui.q qVarP = p(c0814p, nVar3);
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.c, androidx.compose.ui.b.m, c0814p, 0);
            int i4 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, qVarP);
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
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i4))) {
                android.support.v4.media.session.a.z(i4, c0814p, i4, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            m(AbstractC3106b5.d(c0814p, R.string.learn_settings_general_title), c0814p, 0);
            String strD = AbstractC3106b5.d(c0814p, R.string.learn_settings_general_shuffle);
            com.quizlet.themes.m.g.u();
            n(strD, z, function1, "shuffleTag", AbstractC0382e.y(nVar3, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.g, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), c0814p, ((i3 << 3) & ContentType.LONG_FORM_ON_DEMAND) | 3072 | (i3 & 896), 0);
            n(AbstractC3106b5.d(c0814p, R.string.assistant_settings_group_general_audio), z3, function12, "audioTag", null, c0814p, (i3 & ContentType.LONG_FORM_ON_DEMAND) | 3072 | ((i3 >> 3) & 896), 16);
            c0814p.p(true);
            nVar2 = nVar3;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.tabs.c(z, z2, function1, function12, nVar2, i);
        }
    }

    public static final void g(kotlinx.collections.immutable.c cVar, WrittenQuestionGradingOption writtenQuestionGradingOption, boolean z, Function1 function1, Function1 function12, androidx.compose.ui.q qVar, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        Function1 function13;
        C0913i c0913i;
        C0912h c0912h;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1168148220);
        if ((i & 6) == 0) {
            i2 = ((i & 8) == 0 ? c0814p.f(cVar) : c0814p.h(cVar) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= (i & 64) == 0 ? c0814p.f(writtenQuestionGradingOption) : c0814p.h(writtenQuestionGradingOption) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p.g(z) ? 256 : 128;
        }
        if ((i & 3072) == 0) {
            function13 = function1;
            i2 |= c0814p.h(function13) ? 2048 : 1024;
        } else {
            function13 = function1;
        }
        if ((i & 24576) == 0) {
            i2 |= c0814p.h(function12) ? 16384 : 8192;
        }
        if ((196608 & i) == 0) {
            i2 |= c0814p.f(qVar) ? 131072 : 65536;
        }
        int i3 = i2;
        if ((i3 & 74899) == 74898 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.ui.q qVarP = p(c0814p, qVar);
            C0384f c0384f = AbstractC0398m.c;
            androidx.compose.ui.g gVar = androidx.compose.ui.b.m;
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(c0384f, gVar, c0814p, 0);
            int i4 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, qVarP);
            InterfaceC0915k.D0.getClass();
            C0913i c0913i2 = C0914j.b;
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i2);
            } else {
                c0814p.l0();
            }
            C0912h c0912h2 = C0914j.f;
            C0776c.E(c0814p, bA, c0912h2);
            C0912h c0912h3 = C0914j.e;
            C0776c.E(c0814p, interfaceC0803j0L, c0912h3);
            C0912h c0912h4 = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i4))) {
                android.support.v4.media.session.a.z(i4, c0814p, i4, c0912h4);
            }
            C0912h c0912h5 = C0914j.d;
            C0776c.E(c0814p, qVarC, c0912h5);
            String strD = AbstractC3106b5.d(c0814p, R.string.learn_settings_written_grading_title);
            androidx.compose.runtime.B b = com.quizlet.themes.g.a;
            long jE = ((com.quizlet.themes.b) c0814p.j(b)).b.e();
            androidx.compose.runtime.B b2 = com.quizlet.themes.w.a;
            androidx.compose.material3.Q4.b(strD, null, jE, 0L, null, 0L, null, 0L, 0, false, 0, 0, null, ((com.quizlet.themes.f) c0814p.j(b2)).g, c0814p, 0, 0, 65530);
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            com.quizlet.themes.m.g.q();
            int i5 = i3 >> 3;
            com.quizlet.learn.settings.ui.b.a(cVar, writtenQuestionGradingOption, function13, AbstractC0382e.w(nVar, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.i, 1), c0814p, (i3 & 126) | (i5 & 896));
            androidx.compose.material3.Z1.g(null, com.quizlet.themes.m.h, ((com.quizlet.themes.b) c0814p.j(b)).b.i(), c0814p, 0, 1);
            androidx.compose.foundation.layout.B bA2 = androidx.compose.foundation.layout.A.a(c0384f, gVar, c0814p, 0);
            int i6 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L2 = c0814p.l();
            androidx.compose.ui.q qVarC2 = androidx.compose.ui.a.c(c0814p, nVar);
            c0814p.b0();
            if (c0814p.O) {
                c0913i = c0913i2;
                c0814p.k(c0913i);
            } else {
                c0913i = c0913i2;
                c0814p.l0();
            }
            C0776c.E(c0814p, bA2, c0912h2);
            C0776c.E(c0814p, interfaceC0803j0L2, c0912h3);
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i6))) {
                c0912h = c0912h4;
                android.support.v4.media.session.a.z(i6, c0814p, i6, c0912h);
            } else {
                c0912h = c0912h4;
            }
            C0776c.E(c0814p, qVarC2, c0912h5);
            androidx.compose.ui.h hVar = androidx.compose.ui.b.k;
            C0386g c0386g = AbstractC0398m.g;
            androidx.compose.ui.q qVarC3 = androidx.compose.foundation.layout.K0.c(nVar, 1.0f);
            androidx.compose.foundation.layout.G0 g0B = androidx.compose.foundation.layout.E0.b(c0386g, hVar, c0814p, 54);
            int i7 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L3 = c0814p.l();
            androidx.compose.ui.q qVarC4 = androidx.compose.ui.a.c(c0814p, qVarC3);
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0776c.E(c0814p, g0B, c0912h2);
            C0776c.E(c0814p, interfaceC0803j0L3, c0912h3);
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i7))) {
                android.support.v4.media.session.a.z(i7, c0814p, i7, c0912h);
            }
            C0776c.E(c0814p, qVarC4, c0912h5);
            n(AbstractC3106b5.d(c0814p, R.string.assistant_settings_group_general_retype_correct_answer), z, function12, "retypeTag", null, c0814p, (i5 & ContentType.LONG_FORM_ON_DEMAND) | 3072 | ((i3 >> 6) & 896), 16);
            c0814p.p(true);
            androidx.compose.material3.Q4.b(AbstractC3106b5.d(c0814p, R.string.learn_settings_retype_answer_description), null, ((com.quizlet.themes.b) c0814p.j(b)).b.f(), 0L, null, 0L, null, 0L, 0, false, 0, 0, null, ((com.quizlet.themes.f) c0814p.j(b2)).p, c0814p, 0, 0, 65530);
            c0814p = c0814p;
            c0814p.p(true);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.diagrams.ui.f(cVar, writtenQuestionGradingOption, z, function1, function12, qVar, i);
        }
    }

    public static final void h(int i, InterfaceC0806l interfaceC0806l, androidx.compose.ui.q qVar, Function0 function0) {
        int i2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1260098010);
        if ((i & 6) == 0) {
            i2 = (c0814p.h(function0) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.f(qVar) ? 32 : 16;
        }
        if ((i2 & 19) == 18 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.c, androidx.compose.ui.b.m, c0814p, 0);
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
            C0776c.E(c0814p, bA, C0914j.f);
            C0776c.E(c0814p, interfaceC0803j0L, C0914j.e);
            C0912h c0912h = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i3))) {
                android.support.v4.media.session.a.z(i3, c0814p, i3, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            androidx.compose.material3.Q4.b(AbstractC3106b5.d(c0814p, R.string.assistant_settings_personalization_explanation_set_page_simplification), null, 0L, 0L, null, 0L, null, 0L, 0, false, 0, 0, null, ((com.quizlet.themes.f) c0814p.j(com.quizlet.themes.w.a)).o, c0814p, 0, 0, 65534);
            c0814p = c0814p;
            String strD = AbstractC3106b5.d(c0814p, R.string.assistant_settings_personalization_explanation_set_page_simplification_button_turn_off);
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            com.quizlet.themes.m.g.u();
            AbstractC3769y5.a(strD, androidx.compose.foundation.layout.K0.f(AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.g, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), com.quizlet.themes.m.q, DefinitionKt.NO_Float_VALUE, 2), null, null, null, function0, c0814p, (i2 << 15) & 458752, 28);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.buttons.U(function0, qVar, i, 11);
        }
    }

    public static final void i(com.quizlet.quizletandroid.ui.studymodes.assistant.settings.data.m uiState, LearnSettingsUpdateData learnSettingsUpdateData, androidx.compose.ui.n nVar, Function1 function1, Function0 function0, Function1 function12, InterfaceC0806l interfaceC0806l, int i) {
        androidx.compose.ui.n nVar2;
        int i2 = 4;
        Intrinsics.checkNotNullParameter(uiState, "uiState");
        Intrinsics.checkNotNullParameter(learnSettingsUpdateData, "learnSettingsUpdateData");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1969517798);
        int i3 = i | (c0814p.h(uiState) ? 4 : 2) | (c0814p.f(learnSettingsUpdateData) ? 32 : 16) | 384 | (c0814p.h(function1) ? 2048 : 1024) | (c0814p.h(function12) ? 131072 : 65536);
        if ((i3 & 74899) == 74898 && c0814p.x()) {
            c0814p.Q();
            nVar2 = nVar;
        } else {
            androidx.compose.ui.n nVar3 = androidx.compose.ui.n.b;
            androidx.compose.runtime.V v = C0804k.a;
            com.quizlet.assembly.compose.modals.x xVarH = Y5.h(true, uiState.l, c0814p, 6, 4);
            androidx.work.impl.t.a(false, function0, c0814p, 48, 1);
            WeakHashMap weakHashMap = androidx.compose.foundation.layout.S0.w;
            AbstractC0725t3.a(androidx.compose.foundation.layout.U0.a(new C0416v0(C0380d.e(c0814p).l, 16)), androidx.compose.runtime.internal.e.e(-1578304854, new com.quizlet.quizletandroid.ui.startpage.nav2.composables.d(i2, function0), c0814p), null, null, null, 0, 0L, 0L, null, androidx.compose.runtime.internal.e.e(610552885, new C4256l(uiState, learnSettingsUpdateData, function1, function12, function0), c0814p), c0814p, 805306416, 508);
            c0814p = c0814p;
            c0814p.X(1544928198);
            int i4 = i3 & 458752;
            boolean zH = c0814p.h(xVarH) | (i4 == 131072) | ((i3 & ContentType.LONG_FORM_ON_DEMAND) == 32);
            Object objI = c0814p.I();
            if (zH || objI == v) {
                objI = new com.quizlet.quizletandroid.ui.startpage.nav2.viewholder.w(xVarH, function12, learnSettingsUpdateData, i);
                c0814p.i0(objI);
            }
            Function0 function02 = (Function0) objI;
            c0814p.p(false);
            c0814p.X(1544933510);
            int i5 = (c0814p.h(xVarH) ? 1 : 0) | (i4 != 131072 ? 0 : 1);
            Object objI2 = c0814p.I();
            if (i5 != 0 || objI2 == v) {
                objI2 = new com.quizlet.features.folders.addtofolder.composables.j(function12, xVarH, 10);
                c0814p.i0(objI2);
            }
            c0814p.p(false);
            F6.c(xVarH, function02, (Function0) objI2, null, c0814p, 8);
            nVar2 = nVar3;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.explanations.questiondetail.ui.composables.e(uiState, learnSettingsUpdateData, nVar2, function1, function0, function12, i);
        }
    }

    public static final void j(com.quizlet.assembly.compose.modals.x popupState, com.quizlet.quizletandroid.ui.studymodes.assistant.settings.data.m uiState, androidx.compose.ui.n nVar, Function1 function1, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        Intrinsics.checkNotNullParameter(popupState, "popupState");
        Intrinsics.checkNotNullParameter(uiState, "uiState");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-2092504597);
        if ((i & 6) == 0) {
            i2 = ((i & 8) == 0 ? c0814p.f(popupState) : c0814p.h(popupState) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.h(uiState) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p.f(nVar) ? 256 : 128;
        }
        if ((i & 3072) == 0) {
            i2 |= c0814p.h(function1) ? 2048 : 1024;
        }
        int i3 = i2;
        if ((i3 & 1171) == 1170 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.runtime.V v = C0804k.a;
            Object[] objArr = new Object[0];
            c0814p.X(1948559262);
            boolean zH = c0814p.h(uiState);
            Object objI = c0814p.I();
            if (zH || objI == v) {
                objI = new com.quizlet.quizletandroid.ui.studymodes.assistant.settings.o(uiState, 2);
                c0814p.i0(objI);
            }
            c0814p.p(false);
            InterfaceC0773a0 interfaceC0773a0 = (InterfaceC0773a0) com.google.android.gms.internal.mlkit_vision_barcode.L4.d(objArr, null, (Function0) objI, c0814p, 0, 6);
            c0814p.X(1948588357);
            Object objI2 = c0814p.I();
            if (objI2 == v) {
                objI2 = new com.quizlet.features.infra.folder.tag.composable.f(10, interfaceC0773a0, function1);
                c0814p.i0(objI2);
            }
            Function0 function0 = (Function0) objI2;
            c0814p.p(false);
            U5.b(popupState, nVar, false, null, null, function0, androidx.compose.runtime.internal.e.e(832489318, new com.quizlet.assembly.compose.buttons.A(uiState, interfaceC0773a0, function0, function1, 21), c0814p), c0814p, (i3 & 14) | 1769480 | ((i3 >> 3) & ContentType.LONG_FORM_ON_DEMAND), 28);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.quizletandroid.ui.globalnav.composable.d(popupState, uiState, nVar, function1, i, 2);
        }
    }

    public static final void k(int i, InterfaceC0806l interfaceC0806l, androidx.compose.ui.q qVar, Function0 function0) {
        int i2;
        Function0 function02;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1864655376);
        if ((i & 6) == 0) {
            i2 = (c0814p.h(function0) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.f(qVar) ? 32 : 16;
        }
        if ((i2 & 19) == 18 && c0814p.x()) {
            c0814p.Q();
            function02 = function0;
        } else {
            androidx.compose.ui.q qVarP = p(c0814p, androidx.compose.foundation.layout.K0.c(qVar, 1.0f));
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.e, androidx.compose.ui.b.m, c0814p, 6);
            int i3 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, qVarP);
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
            function02 = function0;
            AbstractC3761x5.a(AbstractC3106b5.d(c0814p, R.string.assistant_settings_group_misc_restart), ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).b.a(), null, null, null, null, function02, c0814p, (i2 << 18) & 3670016, 60);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.buttons.U(function02, qVar, i, 10);
        }
    }

    public static final void l(boolean z, Function0 function0, boolean z2, boolean z3, boolean z4, Function1 function1, Function1 function12, Function1 function13, androidx.compose.ui.q qVar, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        Function1 function14;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-796182614);
        if ((i & 6) == 0) {
            i2 = (c0814p.g(z) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.h(function0) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p.g(z2) ? 256 : 128;
        }
        if ((i & 3072) == 0) {
            i2 |= c0814p.g(z3) ? 2048 : 1024;
        }
        if ((i & 24576) == 0) {
            i2 |= c0814p.g(z4) ? 16384 : 8192;
        }
        if ((196608 & i) == 0) {
            function14 = function1;
            i2 |= c0814p.h(function14) ? 131072 : 65536;
        } else {
            function14 = function1;
        }
        if ((1572864 & i) == 0) {
            i2 |= c0814p.h(function12) ? 1048576 : 524288;
        }
        if ((12582912 & i) == 0) {
            i2 |= c0814p.h(function13) ? 8388608 : 4194304;
        }
        if ((100663296 & i) == 0) {
            i2 |= c0814p.f(qVar) ? 67108864 : 33554432;
        }
        int i3 = i2;
        if ((i3 & 38347923) == 38347922 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.ui.q qVarP = p(c0814p, qVar);
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.c, androidx.compose.ui.b.m, c0814p, 0);
            int i4 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, qVarP);
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
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i4))) {
                android.support.v4.media.session.a.z(i4, c0814p, i4, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            m(AbstractC3106b5.d(c0814p, R.string.learn_settings_question_types_title), c0814p, 0);
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            if (z) {
                c0814p.X(390064274);
                com.quizlet.themes.m.g.s();
                h((i3 >> 3) & 14, c0814p, AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.h, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), function0);
                c0814p.p(false);
            } else {
                c0814p.X(390301238);
                String strD = AbstractC3106b5.d(c0814p, R.string.learn_settings_question_types_cards);
                com.quizlet.themes.m.g.u();
                int i5 = i3 >> 9;
                n(strD, z2, function14, "showFlashcardsTag", AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.g, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), c0814p, ((i3 >> 3) & ContentType.LONG_FORM_ON_DEMAND) | 3072 | (i5 & 896), 0);
                n(AbstractC3106b5.d(c0814p, R.string.learn_settings_question_types_mc), z3, function12, "showMultipleChoiceQuestionsTag", null, c0814p, ((i3 >> 6) & ContentType.LONG_FORM_ON_DEMAND) | 3072 | ((i3 >> 12) & 896), 16);
                n(AbstractC3106b5.d(c0814p, R.string.learn_settings_question_types_written), z4, function13, "showWrittenQuestionsTag", null, c0814p, (i5 & ContentType.LONG_FORM_ON_DEMAND) | 3072 | ((i3 >> 15) & 896), 16);
                androidx.compose.animation.E.f((z2 || z3 || z4) ? false : true, null, null, null, null, com.quizlet.quizletandroid.ui.studymodes.assistant.settings.composables.c.c, c0814p, 1572870, 30);
                c0814p = c0814p;
                c0814p.p(false);
            }
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.quizletandroid.ui.studymodes.assistant.settings.m(z, function0, z2, z3, z4, function1, function12, function13, qVar, i, 1);
        }
    }

    public static final void m(String str, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-1629063871);
        int i2 = i | (c0814p2.f(str) ? 4 : 2);
        if ((i2 & 3) == 2 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            c0814p = c0814p2;
            androidx.compose.material3.Q4.b(str, null, ((com.quizlet.themes.b) c0814p2.j(com.quizlet.themes.g.a)).b.e(), 0L, null, 0L, null, 0L, 0, false, 0, 0, null, ((com.quizlet.themes.f) c0814p2.j(com.quizlet.themes.w.a)).g, c0814p, i2 & 14, 0, 65530);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.explanations.solution.recyclerview.step.h(str, i, 3);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:48:0x0088  */
    /* JADX WARN: Removed duplicated region for block: B:49:0x008a  */
    /* JADX WARN: Removed duplicated region for block: B:50:0x008e  */
    /* JADX WARN: Removed duplicated region for block: B:54:0x00c5  */
    /* JADX WARN: Removed duplicated region for block: B:56:? A[RETURN, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void n(java.lang.String r12, boolean r13, kotlin.jvm.functions.Function1 r14, java.lang.String r15, androidx.compose.ui.q r16, androidx.compose.runtime.InterfaceC0806l r17, int r18, int r19) {
        /*
            Method dump skipped, instructions count: 212
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_document_scanner.E6.n(java.lang.String, boolean, kotlin.jvm.functions.Function1, java.lang.String, androidx.compose.ui.q, androidx.compose.runtime.l, int, int):void");
    }

    public static final void o(androidx.compose.ui.q qVar, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-348225933);
        if ((((c0814p.f(qVar) ? 4 : 2) | i) & 3) == 2 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.foundation.layout.G0 g0B = androidx.compose.foundation.layout.E0.b(AbstractC0398m.g, androidx.compose.ui.b.k, c0814p, 54);
            int i2 = c0814p.P;
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
            C0776c.E(c0814p, g0B, C0914j.f);
            C0776c.E(c0814p, interfaceC0803j0L, C0914j.e);
            C0912h c0912h = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i2))) {
                android.support.v4.media.session.a.z(i2, c0814p, i2, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            String strD = AbstractC3106b5.d(c0814p, R.string.learn_settings_enter_write_mode);
            androidx.compose.ui.text.L l = ((com.quizlet.themes.f) c0814p.j(com.quizlet.themes.w.a)).j;
            androidx.compose.runtime.B b = com.quizlet.themes.g.a;
            androidx.compose.material3.Q4.b(strD, null, ((com.quizlet.themes.b) c0814p.j(b)).b.e(), 0L, null, 0L, null, 0L, 0, false, 0, 0, null, l, c0814p, 0, 0, 65530);
            c0814p = c0814p;
            com.quizlet.themes.e.a(c0814p).a.getClass();
            androidx.compose.ui.graphics.painter.b bVarO = com.quizlet.ui.resources.icons.d.o(c0814p);
            long jE = ((com.quizlet.themes.b) c0814p.j(b)).b.e();
            String strD2 = AbstractC3106b5.d(c0814p, R.string.assistant_settings_personalization_enter_write);
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            com.quizlet.themes.m.g.i();
            androidx.compose.material3.D1.a(bVarO, strD2, androidx.compose.foundation.layout.K0.k(nVar, com.quizlet.ui.resources.designsystem.generated.h.f), jE, c0814p, 0, 0);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.cards.d(i, 20, qVar);
        }
    }

    public static final androidx.compose.ui.q p(InterfaceC0806l interfaceC0806l, androidx.compose.ui.q qVar) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.X(-1203628040);
        com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
        mVar.c();
        androidx.compose.ui.q qVarF = AbstractC0460p.f(androidx.compose.ui.draw.g.c(qVar, androidx.compose.foundation.shape.e.a(com.quizlet.ui.resources.designsystem.generated.f.h)), ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).f, androidx.compose.ui.graphics.F.a);
        mVar.s();
        androidx.compose.ui.q qVarU = AbstractC0382e.u(qVarF, com.quizlet.ui.resources.designsystem.generated.j.h);
        c0814p.p(false);
        return qVarU;
    }
}

package androidx.transition;

import android.view.View;
import android.view.ViewGroup;
import androidx.compose.foundation.AbstractC0460p;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.foundation.layout.E0;
import androidx.compose.foundation.layout.FillElement;
import androidx.compose.foundation.layout.G0;
import androidx.compose.foundation.layout.K0;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3347h2;
import com.google.android.gms.internal.mlkit_vision_camera.Q1;
import com.google.android.gms.internal.mlkit_vision_document_scanner.U5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.Y4;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import java.nio.charset.Charset;
import java.util.regex.Pattern;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.Charsets;

/* renamed from: androidx.transition.o, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1412o implements InterfaceC1414q {
    public final /* synthetic */ int a;

    public static final void c(int i, InterfaceC0806l interfaceC0806l, androidx.compose.ui.q qVar, com.quizlet.assembly.compose.modals.x state, Function0 onCloseClick, Function1 onRowClick, kotlinx.collections.immutable.e questionList) {
        Intrinsics.checkNotNullParameter(state, "state");
        Intrinsics.checkNotNullParameter(questionList, "questionList");
        Intrinsics.checkNotNullParameter(onRowClick, "onRowClick");
        Intrinsics.checkNotNullParameter(onCloseClick, "onCloseClick");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1926826867);
        int i2 = (c0814p.h(state) ? 4 : 2) | i | (c0814p.f(questionList) ? 32 : 16) | (c0814p.h(onRowClick) ? 256 : 128) | (c0814p.h(onCloseClick) ? 2048 : 1024) | (c0814p.f(qVar) ? 16384 : 8192);
        if ((i2 & 9363) == 9362 && c0814p.x()) {
            c0814p.Q();
        } else {
            U5.b(state, qVar, false, null, null, null, androidx.compose.runtime.internal.e.e(1852055240, new com.quizlet.assembly.compose.menu.l(questionList, onRowClick, onCloseClick, 18), c0814p), c0814p, (i2 & 14) | 1572872 | ((i2 >> 9) & ContentType.LONG_FORM_ON_DEMAND), 60);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.composables.r(state, questionList, onRowClick, onCloseClick, qVar, i, 7);
        }
    }

    public static final void d(kotlinx.collections.immutable.e eVar, Function1 function1, Function0 function0, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(265925560);
        int i2 = i | (c0814p.f(eVar) ? 4 : 2) | (c0814p.h(function1) ? 32 : 16) | (c0814p.h(function0) ? 256 : 128);
        if ((i2 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            FillElement fillElement = K0.c;
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.g, androidx.compose.ui.b.m, c0814p, 6);
            int i3 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, fillElement);
            InterfaceC0915k.D0.getClass();
            C0913i c0913i = C0914j.b;
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0912h c0912h = C0914j.f;
            C0776c.E(c0814p, bA, c0912h);
            C0912h c0912h2 = C0914j.e;
            C0776c.E(c0814p, interfaceC0803j0L, c0912h2);
            C0912h c0912h3 = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i3))) {
                android.support.v4.media.session.a.z(i3, c0814p, i3, c0912h3);
            }
            C0912h c0912h4 = C0914j.d;
            C0776c.E(c0814p, qVarC, c0912h4);
            androidx.compose.ui.q qVarA = androidx.compose.foundation.layout.C.a(nVar, 1.0f);
            androidx.compose.runtime.B b = com.quizlet.themes.g.a;
            long jG = ((com.quizlet.themes.b) c0814p.j(b)).b.g();
            com.quizlet.shared.usecase.folderstudymaterials.d dVar = androidx.compose.ui.graphics.F.a;
            androidx.compose.ui.q qVarF = AbstractC0460p.f(qVarA, jG, dVar);
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            mVar.s();
            float f = com.quizlet.ui.resources.designsystem.generated.j.h;
            Q1.e(i2 & 126, c0814p, AbstractC0382e.w(qVarF, f, DefinitionKt.NO_Float_VALUE, 2), function1, eVar);
            androidx.compose.ui.q qVarC2 = K0.c(AbstractC0460p.f(nVar, ((com.quizlet.themes.b) c0814p.j(b)).b.g(), dVar), 1.0f);
            G0 g0B = E0.b(AbstractC0398m.a, androidx.compose.ui.b.j, c0814p, 0);
            int i4 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L2 = c0814p.l();
            androidx.compose.ui.q qVarC3 = androidx.compose.ui.a.c(c0814p, qVarC2);
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0776c.E(c0814p, g0B, c0912h);
            C0776c.E(c0814p, interfaceC0803j0L2, c0912h2);
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i4))) {
                android.support.v4.media.session.a.z(i4, c0814p, i4, c0912h3);
            }
            C0776c.E(c0814p, qVarC3, c0912h4);
            androidx.compose.ui.q qVarC4 = K0.c(nVar, 1.0f);
            mVar.s();
            mVar.q();
            Y4.b(AbstractC3106b5.d(c0814p, R.string.close), AbstractC0382e.v(qVarC4, f, com.quizlet.ui.resources.designsystem.generated.j.i), function0, false, null, null, 0L, 0L, null, null, null, c0814p, i2 & 896, 0, 4088);
            c0814p.p(true);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.practicetest.common.composables.m(eVar, function1, function0, i, 1);
        }
    }

    public static okhttp3.E e(int i, okhttp3.w wVar, byte[] bArr) {
        Intrinsics.checkNotNullParameter(bArr, "<this>");
        okhttp3.internal.b.c(bArr.length, 0, i);
        return new okhttp3.E(i, wVar, bArr);
    }

    public static okhttp3.E f(String str, okhttp3.w wVar) {
        Intrinsics.checkNotNullParameter(str, "<this>");
        Charset charset = Charsets.UTF_8;
        if (wVar != null) {
            Pattern pattern = okhttp3.w.e;
            Charset charsetA = wVar.a(null);
            if (charsetA == null) {
                wVar = AbstractC3347h2.d(wVar + "; charset=utf-8");
            } else {
                charset = charsetA;
            }
        }
        byte[] bytes = str.getBytes(charset);
        Intrinsics.checkNotNullExpressionValue(bytes, "this as java.lang.String).getBytes(charset)");
        return e(bytes.length, wVar, bytes);
    }

    public static okhttp3.E g(okhttp3.w wVar, String content) {
        Intrinsics.checkNotNullParameter(content, "content");
        return f(content, wVar);
    }

    @Override // androidx.transition.InterfaceC1414q
    public final float a(View view, ViewGroup viewGroup) {
        switch (this.a) {
            case 0:
                break;
            case 1:
                if (viewGroup.getLayoutDirection() != 1) {
                    break;
                } else {
                    break;
                }
            case 2:
                break;
            default:
                if (viewGroup.getLayoutDirection() != 1) {
                    break;
                } else {
                    break;
                }
        }
        return view.getTranslationX() + viewGroup.getWidth();
    }

    @Override // androidx.transition.InterfaceC1414q
    public float b(View view, ViewGroup viewGroup) {
        return view.getTranslationY();
    }
}

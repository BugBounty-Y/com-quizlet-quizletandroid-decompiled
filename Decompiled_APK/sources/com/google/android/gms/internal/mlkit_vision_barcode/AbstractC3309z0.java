package com.google.android.gms.internal.mlkit_vision_barcode;

import android.content.Context;
import android.content.Intent;
import androidx.compose.foundation.AbstractC0460p;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.graphics.vector.C0867f;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import androidx.compose.ui.text.C0984d;
import androidx.compose.ui.text.C0995g;
import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.features.folders.FolderActivity;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_barcode.z0, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3309z0 {
    public static C0867f a;

    public static final void a(com.quizlet.search.data.typeahead.a searchTypeAheadData, androidx.compose.ui.n nVar, Function1 function1, InterfaceC0806l interfaceC0806l, int i) {
        androidx.compose.ui.n nVar2;
        Intrinsics.checkNotNullParameter(searchTypeAheadData, "searchTypeAheadData");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1209938358);
        int i2 = i | (c0814p.f(searchTypeAheadData) ? 4 : 2) | 48 | (c0814p.h(function1) ? 256 : 128);
        if ((i2 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
            nVar2 = nVar;
        } else {
            androidx.compose.ui.n nVar3 = androidx.compose.ui.n.b;
            androidx.compose.runtime.V v = C0804k.a;
            androidx.compose.ui.h hVar = androidx.compose.ui.b.k;
            c0814p.X(2072082223);
            boolean zF = ((i2 & 896) == 256) | c0814p.f(searchTypeAheadData);
            Object objI = c0814p.I();
            if (zF || objI == v) {
                objI = new com.quizlet.quizletandroid.ui.startpage.nav2.viewholder.v(8, function1, searchTypeAheadData);
                c0814p.i0(objI);
            }
            c0814p.p(false);
            androidx.compose.ui.q qVarL = AbstractC0460p.l(nVar3, false, null, (Function0) objI, 7);
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            mVar.s();
            androidx.compose.ui.q qVarC = androidx.compose.foundation.layout.K0.c(AbstractC0382e.u(qVarL, com.quizlet.ui.resources.designsystem.generated.j.h), 1.0f);
            androidx.compose.foundation.layout.G0 g0B = androidx.compose.foundation.layout.E0.b(AbstractC0398m.a, hVar, c0814p, 48);
            int i3 = c0814p.P;
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
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i3))) {
                android.support.v4.media.session.a.z(i3, c0814p, i3, c0912h);
            }
            C0776c.E(c0814p, qVarC2, C0914j.d);
            com.quizlet.themes.e.a(c0814p).a.getClass();
            androidx.compose.ui.graphics.painter.b bVarH = com.quizlet.ui.resources.icons.d.H(c0814p);
            String strD = AbstractC3106b5.d(c0814p, R.string.search);
            long jF = ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).b.f();
            mVar.i();
            androidx.compose.material3.D1.a(bVarH, strD, androidx.compose.ui.platform.N.G(androidx.compose.foundation.layout.K0.k(nVar3, com.quizlet.ui.resources.designsystem.generated.h.f), "typeAheadIcon"), jF, c0814p, 0, 0);
            C0984d c0984d = new C0984d();
            c0984d.f(searchTypeAheadData.b);
            c0984d.c(new androidx.compose.ui.text.D(0L, 0L, androidx.compose.ui.text.font.u.i, (androidx.compose.ui.text.font.q) null, (androidx.compose.ui.text.font.r) null, (androidx.compose.ui.text.font.j) null, (String) null, 0L, (androidx.compose.ui.text.style.a) null, (androidx.compose.ui.text.style.o) null, (androidx.compose.ui.text.intl.b) null, 0L, (androidx.compose.ui.text.style.j) null, (androidx.compose.ui.graphics.U) null, 65531), searchTypeAheadData.a.length(), searchTypeAheadData.b.length());
            C0995g c0995gJ = c0984d.j();
            androidx.compose.ui.text.L l = ((com.quizlet.themes.f) c0814p.j(com.quizlet.themes.w.b)).o;
            mVar.u();
            androidx.compose.material3.Q4.c(c0995gJ, AbstractC0382e.y(nVar3, com.quizlet.ui.resources.designsystem.generated.j.g, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 14), 0L, 0L, null, 0L, null, 0L, 0, false, 0, 0, null, null, l, c0814p, 0, 0, 131068);
            c0814p = c0814p;
            c0814p.p(true);
            nVar2 = nVar3;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.quizletandroid.ui.startpage.nav2.composables.f(i, 15, searchTypeAheadData, nVar2, function1);
        }
    }

    public static Intent b(Context context, long j) {
        Intent intentB = AbstractC4178x.b(context, "context", context, FolderActivity.class);
        intentB.putExtra("folderId", j);
        return intentB;
    }
}

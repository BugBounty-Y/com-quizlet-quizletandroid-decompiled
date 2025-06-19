package com.quizlet.baseui.base;

import android.app.Dialog;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import androidx.compose.foundation.AbstractC0460p;
import androidx.compose.foundation.layout.AbstractC0409s;
import androidx.compose.foundation.layout.C0418x;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.draw.g;
import androidx.compose.ui.layout.K;
import androidx.compose.ui.n;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import androidx.compose.ui.platform.ComposeView;
import androidx.compose.ui.q;
import androidx.navigation.compose.C1278k;
import com.comscore.streaming.ContentType;
import com.google.android.material.bottomsheet.h;
import com.google.android.material.bottomsheet.i;
import com.quizlet.quizletandroid.R;
import com.quizlet.themes.m;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes2.dex */
public abstract class BaseComposeBottomSheetFragment extends i {
    @Override // androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t
    public final int I() {
        return R.style.CustomBottomSheetDialog;
    }

    @Override // com.google.android.material.bottomsheet.i, androidx.appcompat.app.E, androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t
    public final Dialog K(Bundle bundle) {
        h hVar = (h) super.K(bundle);
        hVar.setOnShowListener(new com.onetrust.otpublishers.headless.UI.TVUI.fragments.e(this, 14));
        return hVar;
    }

    public final void Q(InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-454808522);
        int i2 = (c0814p.f(this) ? 4 : 2) | i;
        if ((i2 & 3) == 2 && c0814p.x()) {
            c0814p.Q();
        } else {
            R(androidx.compose.runtime.internal.e.e(-2039254475, new d(this, 0), c0814p), c0814p, ((i2 << 3) & ContentType.LONG_FORM_ON_DEMAND) | 6);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C1278k(this, i, 1);
        }
    }

    public final void R(androidx.compose.runtime.internal.d dVar, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1638309942);
        if ((i & 6) == 0) {
            i2 = (c0814p.h(dVar) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i2 & 3) == 2 && c0814p.x()) {
            c0814p.Q();
        } else {
            m mVar = m.g;
            mVar.f();
            float f = com.quizlet.ui.resources.designsystem.generated.f.i;
            mVar.f();
            androidx.compose.foundation.shape.d dVarB = androidx.compose.foundation.shape.e.b(f, f, 12);
            q qVarF = AbstractC0460p.f(g.c(n.b, dVarB), ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).b.g(), dVarB);
            int i3 = (i2 << 9) & 7168;
            K kE = AbstractC0409s.e(androidx.compose.ui.b.a, false);
            int i4 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            q qVarC = androidx.compose.ui.a.c(c0814p, qVarF);
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
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i4))) {
                android.support.v4.media.session.a.z(i4, c0814p, i4, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            dVar.invoke(C0418x.a, c0814p, Integer.valueOf(((i3 >> 6) & ContentType.LONG_FORM_ON_DEMAND) | 6));
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.progress.a(this, dVar, i, 3);
        }
    }

    public abstract void S(InterfaceC0806l interfaceC0806l, int i);

    @Override // androidx.fragment.app.Fragment
    public final View onCreateView(LayoutInflater inflater, ViewGroup viewGroup, Bundle bundle) {
        Intrinsics.checkNotNullParameter(inflater, "inflater");
        return inflater.inflate(R.layout.fragment_compose_bottom_sheet, viewGroup, false);
    }

    @Override // androidx.fragment.app.Fragment
    public void onViewCreated(View view, Bundle bundle) {
        Intrinsics.checkNotNullParameter(view, "view");
        super.onViewCreated(view, bundle);
        ((ComposeView) view.findViewById(R.id.compose_view)).setContent(new androidx.compose.runtime.internal.d(true, 1263254056, new e(this, 1)));
    }
}

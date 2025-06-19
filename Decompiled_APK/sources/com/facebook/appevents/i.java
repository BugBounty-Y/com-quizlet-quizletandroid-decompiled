package com.facebook.appevents;

import android.content.res.TypedArray;
import android.view.View;
import android.view.ViewParent;
import android.view.inputmethod.EditorInfo;
import android.view.inputmethod.InputConnection;
import android.widget.TextView;
import androidx.compose.foundation.layout.AbstractC0409s;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.layout.K;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import com.google.android.gms.internal.mlkit_vision_document_scanner.Y4;
import com.google.android.gms.measurement.internal.Z;
import com.quizlet.assembly.compose.buttons.C4093s;
import com.quizlet.features.achievements.ui.composables.C4215b;
import com.quizlet.quizletandroid.R;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public abstract class i {
    public static final void a(int i, InterfaceC0806l interfaceC0806l, androidx.compose.ui.q qVar, Function0 onClick, boolean z) {
        int i2;
        int i3;
        Intrinsics.checkNotNullParameter(onClick, "onClick");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(936832479);
        int i4 = i | (c0814p.g(z) ? 4 : 2) | (c0814p.h(onClick) ? 32 : 16);
        if ((i4 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
        } else {
            K kE = AbstractC0409s.e(androidx.compose.ui.b.e, false);
            int i5 = c0814p.P;
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
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i5))) {
                android.support.v4.media.session.a.z(i5, c0814p, i5, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            if (z) {
                i2 = 1177471508;
                i3 = R.string.achievements_badge_view_less;
            } else {
                i2 = 1177561749;
                i3 = R.string.achievements_badge_view_all;
            }
            Y4.b(Z.h(c0814p, i2, i3, c0814p, false), null, onClick, false, null, null, 0L, 0L, C4093s.a, null, null, c0814p, (i4 << 3) & 896, 0, 3578);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C4215b(z, onClick, qVar, i, 0);
        }
    }

    public static final Integer b(TypedArray typedArray, int i, int i2) {
        Intrinsics.checkNotNullParameter(typedArray, "<this>");
        if (typedArray.hasValue(i)) {
            return Integer.valueOf(typedArray.getResourceId(i, i2));
        }
        return null;
    }

    public static void c(InputConnection inputConnection, EditorInfo editorInfo, TextView textView) {
        if (inputConnection == null || editorInfo.hintText != null) {
            return;
        }
        for (ViewParent parent = textView.getParent(); parent instanceof View; parent = parent.getParent()) {
        }
    }

    public static final synchronized void d(com.bumptech.glide.f eventsToPersist) {
        if (com.facebook.internal.instrument.crashshield.a.b(i.class)) {
            return;
        }
        try {
            Intrinsics.checkNotNullParameter(eventsToPersist, "eventsToPersist");
            t tVarH = g.h();
            for (b bVar : eventsToPersist.e()) {
                u uVarB = eventsToPersist.b(bVar);
                if (uVarB == null) {
                    throw new IllegalStateException("Required value was null.");
                }
                tVarH.a(bVar, uVarB.b());
            }
            g.i(tVarH);
        } catch (Throwable th) {
            com.facebook.internal.instrument.crashshield.a.a(i.class, th);
        }
    }

    public static final synchronized void e(b accessTokenAppIdPair, u appEvents) {
        if (com.facebook.internal.instrument.crashshield.a.b(i.class)) {
            return;
        }
        try {
            Intrinsics.checkNotNullParameter(accessTokenAppIdPair, "accessTokenAppIdPair");
            Intrinsics.checkNotNullParameter(appEvents, "appEvents");
            t tVarH = g.h();
            tVarH.a(accessTokenAppIdPair, appEvents.b());
            g.i(tVarH);
        } catch (Throwable th) {
            com.facebook.internal.instrument.crashshield.a.a(i.class, th);
        }
    }
}

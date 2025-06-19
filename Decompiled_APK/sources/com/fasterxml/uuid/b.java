package com.fasterxml.uuid;

import androidx.camera.camera2.internal.G;
import androidx.camera.camera2.internal.P;
import androidx.camera.core.impl.AbstractC0171j;
import androidx.camera.core.impl.AbstractC0172k;
import androidx.compose.foundation.AbstractC0460p;
import androidx.compose.foundation.layout.A;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.foundation.layout.B;
import androidx.compose.foundation.layout.C0386g;
import androidx.compose.foundation.layout.K0;
import androidx.compose.material3.Q4;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.g;
import androidx.compose.ui.n;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import androidx.compose.ui.q;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.google.android.gms.internal.mlkit_vision_barcode.Z4;
import com.google.android.gms.internal.mlkit_vision_document_scanner.Y4;
import com.quizlet.assembly.compose.buttons.U;
import com.quizlet.quizletandroid.R;
import com.quizlet.themes.e;
import com.quizlet.themes.f;
import com.quizlet.themes.m;
import com.quizlet.themes.w;
import com.quizlet.ui.resources.designsystem.generated.j;
import com.skydoves.balloon.internals.DefinitionKt;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public abstract class b {
    public static c a;

    public static final void a(int i, InterfaceC0806l interfaceC0806l, q qVar, Function0 onReloadButtonClicked) {
        int i2;
        Intrinsics.checkNotNullParameter(onReloadButtonClicked, "onReloadButtonClicked");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1018477299);
        if ((i & 6) == 0) {
            i2 = (c0814p.h(onReloadButtonClicked) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.f(qVar) ? 32 : 16;
        }
        if ((i2 & 19) == 18 && c0814p.x()) {
            c0814p.Q();
        } else {
            C0386g c0386g = AbstractC0398m.e;
            g gVar = androidx.compose.ui.b.n;
            q qVarG = qVar.g(K0.c);
            B bA = A.a(c0386g, gVar, c0814p, 54);
            int i3 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            q qVarC = androidx.compose.ui.a.c(c0814p, qVarG);
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
            e.a(c0814p).d.getClass();
            c0814p.X(-1149281092);
            androidx.compose.ui.graphics.painter.b bVarA = Z4.a(R.drawable.ic_brand_no_internet, c0814p, 0);
            c0814p.p(false);
            AbstractC0460p.c(bVarA, null, null, null, null, DefinitionKt.NO_Float_VALUE, null, c0814p, 48, 124);
            Q4.b(AbstractC3106b5.d(c0814p, R.string.achievements_offline_error_description), null, 0L, 0L, null, 0L, null, 0L, 0, false, 0, 0, null, ((f) c0814p.j(w.b)).k, c0814p, 0, 0, 65534);
            String strD = AbstractC3106b5.d(c0814p, R.string.achievements_offline_error_reload_button);
            n nVar = n.b;
            m.g.q();
            Y4.b(strD, AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, j.i, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), onReloadButtonClicked, false, null, null, 0L, 0L, null, null, null, c0814p, (i2 << 6) & 896, 0, 4088);
            c0814p = c0814p;
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new U(onReloadButtonClicked, qVar, i, 3);
        }
    }

    public static String b(InputStream inputStream) throws IOException {
        BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(inputStream));
        StringBuilder sb = new StringBuilder();
        while (true) {
            String line = bufferedReader.readLine();
            if (line == null) {
                return sb.toString();
            }
            sb.append(line);
            sb.append("\n");
        }
    }

    public static void c(AbstractC0171j abstractC0171j, ArrayList arrayList) {
        if (abstractC0171j instanceof AbstractC0172k) {
            ((AbstractC0172k) abstractC0171j).getClass();
            throw null;
        }
        if (abstractC0171j instanceof P) {
            arrayList.add(((P) abstractC0171j).a);
        } else {
            arrayList.add(new G(abstractC0171j));
        }
    }
}

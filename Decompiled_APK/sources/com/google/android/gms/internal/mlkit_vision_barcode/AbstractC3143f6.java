package com.google.android.gms.internal.mlkit_vision_barcode;

import android.content.Context;
import android.content.res.Resources;
import android.graphics.RectF;
import android.widget.ImageView;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.text.C0995g;
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3667l6;
import com.quizlet.quizletandroid.R;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_barcode.f6, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3143f6 {
    public static final void a(androidx.compose.material3.L3 snackbarData, com.quizlet.features.infra.folder.menu.composable.i visuals, Function1 onClick, androidx.compose.ui.q qVar, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        Intrinsics.checkNotNullParameter(snackbarData, "snackbarData");
        Intrinsics.checkNotNullParameter(visuals, "visuals");
        Intrinsics.checkNotNullParameter(onClick, "onClick");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-586852959);
        if ((i & 6) == 0) {
            i2 = (c0814p.f(snackbarData) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.f(visuals) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p.h(onClick) ? 256 : 128;
        }
        int i3 = i2 | 3072;
        if ((i3 & 1171) == 1170 && c0814p.x()) {
            c0814p.Q();
        } else {
            qVar = androidx.compose.ui.n.b;
            com.quizlet.themes.m.g.s();
            androidx.compose.ui.q qVarU = AbstractC0382e.u(qVar, com.quizlet.ui.resources.designsystem.generated.j.h);
            C0995g c0995gB = visuals.a.b(c0814p);
            com.quizlet.data.interactor.folderstudymaterial.g gVarA = visuals.a.a();
            c0814p.X(1429220321);
            String strD = gVarA == null ? null : AbstractC3106b5.d(c0814p, R.string.undo);
            c0814p.p(false);
            c0814p.X(1429222679);
            boolean z = ((i3 & ContentType.LONG_FORM_ON_DEMAND) == 32) | ((i3 & 896) == 256) | ((i3 & 14) == 4);
            Object objI = c0814p.I();
            if (z || objI == C0804k.a) {
                objI = new androidx.work.impl.utils.q(visuals, onClick, snackbarData, 14);
                c0814p.i0(objI);
            }
            c0814p.p(false);
            AbstractC3667l6.c(c0995gB, qVarU, strD, (Function0) objI, null, null, c0814p, 0, 104);
        }
        androidx.compose.ui.q qVar2 = qVar;
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.menu.i((Object) snackbarData, (Object) visuals, (Object) onClick, qVar2, i, 11);
        }
    }

    public static final void d(ImageView imageView, int i) throws Resources.NotFoundException {
        Intrinsics.checkNotNullParameter(imageView, "<this>");
        Context context = imageView.getContext();
        Intrinsics.checkNotNullExpressionValue(context, "getContext(...)");
        Intrinsics.checkNotNullParameter(context, "<this>");
        int dimensionPixelSize = context.getResources().getDimensionPixelSize(i);
        imageView.getLayoutParams().width = dimensionPixelSize;
        imageView.getLayoutParams().height = dimensionPixelSize;
    }

    public abstract RectF b(androidx.constraintlayout.motion.widget.r rVar, RectF rectF);

    public abstract void c(boolean z);
}

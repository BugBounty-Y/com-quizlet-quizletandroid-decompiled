package com.google.android.gms.internal.mlkit_vision_camera;

import androidx.compose.foundation.text.AbstractC0484d0;
import androidx.compose.material3.Q4;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.text.C0984d;
import androidx.compose.ui.text.C0995g;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.google.android.gms.internal.mlkit_vision_barcode.S5;
import com.quizlet.quizletandroid.R;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.List;
import kotlin.Pair;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt__StringsKt;

/* renamed from: com.google.android.gms.internal.mlkit_vision_camera.e, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3332e {
    public static final void a(com.quizlet.data.model.m2 source, androidx.compose.ui.q qVar, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        Pair pair;
        long jE;
        long jF;
        C0814p c0814p;
        int i3 = 0;
        int i4 = 4;
        Intrinsics.checkNotNullParameter(source, "source");
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-1717030755);
        if ((i & 6) == 0) {
            i2 = (c0814p2.f(source) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p2.f(qVar) ? 32 : 16;
        }
        if ((i2 & 19) == 18 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            c0814p2.X(-1363654479);
            int iOrdinal = source.ordinal();
            if (iOrdinal == 0) {
                c0814p2.X(-674878517);
                pair = new Pair(AbstractC3106b5.d(c0814p2, R.string.upload_flashcards), AbstractC3106b5.d(c0814p2, R.string.upload_study_guide_disclaimer_text));
                c0814p2.p(false);
            } else {
                if (iOrdinal != 1) {
                    if (iOrdinal != 2) {
                        throw com.google.android.gms.measurement.internal.Z.j(-674885558, c0814p2, false);
                    }
                    c0814p2.X(-674873656);
                    c0814p2.p(false);
                    throw new kotlin.n(null, 1, null);
                }
                c0814p2.X(-674883669);
                pair = new Pair(AbstractC3106b5.d(c0814p2, R.string.upload_study_guide), AbstractC3106b5.d(c0814p2, R.string.upload_flashcards_disclaimer_text));
                c0814p2.p(false);
            }
            c0814p2.p(false);
            String str = (String) pair.a;
            List listSplit$default = StringsKt__StringsKt.split$default((String) pair.b, new String[]{"%1$s"}, false, 0, 6, null);
            boolean zB = Intrinsics.b(listSplit$default.get(0), str);
            c0814p2.X(-1167028294);
            C0984d c0984d = new C0984d();
            if (zB) {
                c0814p2.X(-1177195128);
                jE = ((com.quizlet.themes.b) c0814p2.j(com.quizlet.themes.g.a)).b.f();
                c0814p2.p(false);
            } else {
                c0814p2.X(-1177107894);
                jE = ((com.quizlet.themes.b) c0814p2.j(com.quizlet.themes.g.a)).b.e();
                c0814p2.p(false);
            }
            int i5 = c0984d.i(new androidx.compose.ui.text.D(jE, 0L, (androidx.compose.ui.text.font.u) null, (androidx.compose.ui.text.font.q) null, (androidx.compose.ui.text.font.r) null, (androidx.compose.ui.text.font.j) null, (String) null, 0L, (androidx.compose.ui.text.style.a) null, (androidx.compose.ui.text.style.o) null, (androidx.compose.ui.text.intl.b) null, 0L, (androidx.compose.ui.text.style.j) null, (androidx.compose.ui.graphics.U) null, 65534));
            try {
                c0984d.f((String) listSplit$default.get(0));
                Unit unit = Unit.a;
                c0984d.h(i5);
                AbstractC0484d0.p(c0984d, "image");
                if (zB) {
                    c0814p2.X(-1176816246);
                    jF = ((com.quizlet.themes.b) c0814p2.j(com.quizlet.themes.g.a)).b.e();
                    c0814p2.p(false);
                } else {
                    c0814p2.X(-1176730903);
                    jF = ((com.quizlet.themes.b) c0814p2.j(com.quizlet.themes.g.a)).b.f();
                    c0814p2.p(false);
                }
                i5 = c0984d.i(new androidx.compose.ui.text.D(jF, 0L, (androidx.compose.ui.text.font.u) null, (androidx.compose.ui.text.font.q) null, (androidx.compose.ui.text.font.r) null, (androidx.compose.ui.text.font.j) null, (String) null, 0L, (androidx.compose.ui.text.style.a) null, (androidx.compose.ui.text.style.o) null, (androidx.compose.ui.text.intl.b) null, 0L, (androidx.compose.ui.text.style.j) null, (androidx.compose.ui.graphics.U) null, 65534));
                try {
                    c0984d.f((String) listSplit$default.get(1));
                    c0984d.h(i5);
                    C0995g c0995gJ = c0984d.j();
                    c0814p2.p(false);
                    c0814p = c0814p2;
                    Q4.c(c0995gJ, androidx.compose.foundation.layout.K0.c(qVar, 1.0f), 0L, 0L, null, 0L, new androidx.compose.ui.text.style.i(3), 0L, 0, false, 0, 0, kotlin.collections.U.b(new Pair("image", new androidx.compose.foundation.text.Z(new androidx.compose.ui.text.v(S5.g(24), S5.g(24), 7), androidx.compose.runtime.internal.e.e(-1449066307, new com.quizlet.baseui.base.d(source, i4), c0814p2)))), null, ((com.quizlet.themes.f) c0814p2.j(com.quizlet.themes.w.b)).k, c0814p, 0, 0, 97788);
                } finally {
                }
            } finally {
            }
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.notes.upload.composables.upload.a(source, qVar, i, i3);
        }
    }

    public static void b(InputStream inputStream, OutputStream out) throws IOException {
        Intrinsics.checkNotNullParameter(inputStream, "<this>");
        Intrinsics.checkNotNullParameter(out, "out");
        byte[] bArr = new byte[8192];
        int i = inputStream.read(bArr);
        while (i >= 0) {
            out.write(bArr, 0, i);
            i = inputStream.read(bArr);
        }
    }

    public static final androidx.glance.p c(androidx.glance.p pVar) {
        return pVar.d(new androidx.glance.layout.m(androidx.glance.unit.e.a));
    }

    public static final androidx.glance.p d(androidx.glance.p pVar) {
        return c(e(pVar));
    }

    public static final androidx.glance.p e(androidx.glance.p pVar) {
        return pVar.d(new androidx.glance.layout.t(androidx.glance.unit.e.a));
    }

    public static final androidx.glance.p f(androidx.glance.p pVar, float f) {
        return pVar.d(new androidx.glance.layout.m(new androidx.glance.unit.c(f)));
    }
}

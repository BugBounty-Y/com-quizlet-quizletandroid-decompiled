package com.google.android.gms.internal.mlkit_vision_camera;

import androidx.compose.material3.Q4;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.text.C0981a;
import com.quizlet.quizletandroid.R;
import java.io.Closeable;
import kotlin.C4937f;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_camera.f, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3336f {
    public static final void a(com.quizlet.data.model.m2 source, androidx.compose.ui.q qVar, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        int i3;
        int i4;
        C0814p c0814p;
        Intrinsics.checkNotNullParameter(source, "source");
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(509705309);
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
            c0814p2.X(121486710);
            int iOrdinal = source.ordinal();
            if (iOrdinal == 0) {
                i3 = -674955917;
                i4 = R.string.upload_study_guide_title;
            } else {
                if (iOrdinal != 1) {
                    if (iOrdinal != 2) {
                        throw com.google.android.gms.measurement.internal.Z.j(-674960665, c0814p2, false);
                    }
                    c0814p2.X(-674952824);
                    c0814p2.p(false);
                    throw new kotlin.n(null, 1, null);
                }
                i3 = -674958958;
                i4 = R.string.upload_flashcards_title;
            }
            String strH = com.google.android.gms.measurement.internal.Z.h(c0814p2, i3, i4, c0814p2, false);
            c0814p2.p(false);
            c0814p = c0814p2;
            Q4.b(strH, androidx.compose.foundation.layout.K0.c(qVar, 1.0f), 0L, 0L, null, 0L, new androidx.compose.ui.text.style.i(3), 0L, 0, false, 0, 0, null, ((com.quizlet.themes.f) c0814p2.j(com.quizlet.themes.w.b)).f, c0814p, 0, 0, 65020);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.notes.upload.composables.upload.a(source, qVar, i, 1);
        }
    }

    public static final void b(androidx.glance.p pVar, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1380468206);
        if ((((c0814p.f(pVar) ? 4 : 2) | i) & 3) == 2 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.glance.layout.s sVar = androidx.glance.layout.s.a;
            c0814p.Y(-1115894518);
            c0814p.Y(1886828752);
            if (!(c0814p.a instanceof androidx.glance.b)) {
                C0776c.s();
                throw null;
            }
            c0814p.V();
            if (c0814p.O) {
                c0814p.k(new androidx.compose.ui.input.nestedscroll.b(sVar));
            } else {
                c0814p.l0();
            }
            C0776c.E(c0814p, pVar, androidx.glance.layout.e.j);
            c0814p.p(true);
            c0814p.p(false);
            c0814p.p(false);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C0981a(pVar, i, 3);
        }
    }

    public static final void c(Closeable closeable, Throwable th) {
        if (closeable != null) {
            if (th == null) {
                closeable.close();
                return;
            }
            try {
                closeable.close();
            } catch (Throwable th2) {
                C4937f.a(th, th2);
            }
        }
    }
}

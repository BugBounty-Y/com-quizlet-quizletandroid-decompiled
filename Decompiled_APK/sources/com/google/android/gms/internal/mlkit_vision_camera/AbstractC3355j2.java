package com.google.android.gms.internal.mlkit_vision_camera;

import android.database.sqlite.SQLiteDatabase;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.quizlet.generated.enums.EnumC4501m0;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_camera.j2, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3355j2 {
    public static final void a(String userAnswer, String correctAnswer, EnumC4501m0 grade, androidx.compose.ui.q qVar, InterfaceC0806l interfaceC0806l, int i) {
        Intrinsics.checkNotNullParameter(userAnswer, "userAnswer");
        Intrinsics.checkNotNullParameter(correctAnswer, "correctAnswer");
        Intrinsics.checkNotNullParameter(grade, "grade");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1850013550);
        int i2 = i | (c0814p.f(userAnswer) ? 4 : 2) | (c0814p.f(correctAnswer) ? 32 : 16) | (c0814p.f(grade) ? 256 : 128) | (c0814p.f(qVar) ? 2048 : 1024);
        if ((i2 & 1171) == 1170 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.ui.q qVarC = androidx.compose.foundation.layout.K0.c(qVar, 1.0f);
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.c, androidx.compose.ui.b.m, c0814p, 0);
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
            C0776c.E(c0814p, bA, C0914j.f);
            C0776c.E(c0814p, interfaceC0803j0L, C0914j.e);
            C0912h c0912h = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i3))) {
                android.support.v4.media.session.a.z(i3, c0814p, i3, c0912h);
            }
            C0776c.E(c0814p, qVarC2, C0914j.d);
            int i4 = com.quizlet.features.practicetest.results.composables.b.a[grade.ordinal()];
            if (i4 != 1) {
                androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
                if (i4 == 2) {
                    c0814p.X(-323870537);
                    AbstractC3359k2.a(i2 & 14, 14, c0814p, null, userAnswer, null);
                    com.quizlet.themes.m.g.s();
                    androidx.compose.ui.q qVarY = AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.h, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13);
                    androidx.compose.runtime.B b = com.quizlet.themes.g.a;
                    AbstractC3347h2.a(correctAnswer, qVarY, ((com.quizlet.themes.b) c0814p.j(b)).b.f(), ((com.quizlet.themes.b) c0814p.j(b)).b.e(), null, c0814p, (i2 >> 3) & 14, 48);
                    c0814p.p(false);
                } else if (i4 == 3) {
                    c0814p.X(-323412264);
                    R1.c(0, 2, c0814p, null, AbstractC3106b5.d(c0814p, R.string.practice_test_results_unanswered));
                    com.quizlet.themes.m.g.s();
                    AbstractC3363l2.a((i2 >> 3) & 14, 12, c0814p, AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.h, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), correctAnswer, null);
                    c0814p.p(false);
                } else {
                    if (i4 != 4) {
                        throw com.google.android.gms.measurement.internal.Z.j(-287547320, c0814p, false);
                    }
                    c0814p.X(-323044728);
                    c0814p.p(false);
                }
            } else {
                c0814p.X(-324002256);
                AbstractC3347h2.a(userAnswer, null, 0L, 0L, null, c0814p, i2 & 14, 62);
                c0814p.p(false);
            }
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.features.flashcards.creatormarketing.i(userAnswer, correctAnswer, grade, qVar, i, 21);
        }
    }

    public static okhttp3.x b(String name, String str, okhttp3.F body) {
        Intrinsics.checkNotNullParameter(name, "name");
        Intrinsics.checkNotNullParameter(body, "body");
        StringBuilder sb = new StringBuilder();
        sb.append("form-data; name=");
        okhttp3.w wVar = okhttp3.y.e;
        AbstractC3351i2.b(name, sb);
        if (str != null) {
            sb.append("; filename=");
            AbstractC3351i2.b(str, sb);
        }
        String string = sb.toString();
        Intrinsics.checkNotNullExpressionValue(string, "StringBuilder().apply(builderAction).toString()");
        com.android.billingclient.api.h hVar = new com.android.billingclient.api.h(3);
        hVar.c("Content-Disposition", string);
        okhttp3.r rVarD = hVar.d();
        Intrinsics.checkNotNullParameter(body, "body");
        if (rVarD.a("Content-Type") != null) {
            throw new IllegalArgumentException("Unexpected header: Content-Type");
        }
        if (rVarD.a("Content-Length") == null) {
            return new okhttp3.x(rVarD, body);
        }
        throw new IllegalArgumentException("Unexpected header: Content-Length");
    }

    public static androidx.sqlite.db.framework.b c(com.airbnb.lottie.network.c refHolder, SQLiteDatabase sqLiteDatabase) {
        Intrinsics.checkNotNullParameter(refHolder, "refHolder");
        Intrinsics.checkNotNullParameter(sqLiteDatabase, "sqLiteDatabase");
        androidx.sqlite.db.framework.b bVar = (androidx.sqlite.db.framework.b) refHolder.b;
        if (bVar != null) {
            Intrinsics.checkNotNullParameter(sqLiteDatabase, "sqLiteDatabase");
            if (Intrinsics.b(bVar.a, sqLiteDatabase)) {
                return bVar;
            }
        }
        androidx.sqlite.db.framework.b bVar2 = new androidx.sqlite.db.framework.b(sqLiteDatabase);
        refHolder.b = bVar2;
        return bVar2;
    }
}

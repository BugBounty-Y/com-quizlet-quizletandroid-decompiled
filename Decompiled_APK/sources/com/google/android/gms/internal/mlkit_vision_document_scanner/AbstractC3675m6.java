package com.google.android.gms.internal.mlkit_vision_document_scanner;

import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0409s;
import androidx.compose.foundation.layout.C0374a;
import androidx.compose.foundation.layout.C0380d;
import androidx.compose.foundation.layout.C0416v0;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import androidx.compose.ui.q;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3205m5;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3266t5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3675m6;
import com.quizlet.data.model.InterfaceC4176w0;
import com.quizlet.features.infra.models.studymodeshared.StudyableModelData;
import com.quizlet.quizletandroid.ui.studymodes.assistant.LearningAssistantActivity;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.List;
import java.util.Set;
import java.util.WeakHashMap;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_document_scanner.m6, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3675m6 {
    public static final void a(final String title, androidx.compose.ui.q qVar, final androidx.compose.ui.q qVar2, final androidx.compose.ui.graphics.painter.b bVar, final Function0 function0, long j, long j2, long j3, int i, final com.quizlet.data.repository.achievements.h hVar, int i2, InterfaceC0806l interfaceC0806l, final int i3) {
        int i4;
        androidx.compose.ui.q qVar3;
        long j4;
        int i5;
        long j5;
        int i6;
        long j6;
        androidx.compose.ui.q qVar4;
        int i7;
        float f;
        final long j7;
        final long j8;
        final int i8;
        final androidx.compose.ui.q qVar5;
        final long j9;
        final int i9;
        Intrinsics.checkNotNullParameter(title, "title");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1034870146);
        int i10 = i3 | (c0814p.f(title) ? 4 : 2) | 48 | (c0814p.f(qVar2) ? 256 : 128) | (c0814p.h(bVar) ? 2048 : 1024) | (c0814p.h(function0) ? 16384 : 8192) | 105447424 | (c0814p.f(hVar) ? 536870912 : 268435456);
        if ((306783379 & i10) == 306783378 && c0814p.x()) {
            c0814p.Q();
            qVar5 = qVar;
            j7 = j;
            j8 = j2;
            j9 = j3;
            i9 = i;
            i8 = i2;
        } else {
            c0814p.S();
            if ((i3 & 1) == 0 || c0814p.w()) {
                androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
                androidx.compose.runtime.B b = com.quizlet.themes.g.a;
                long jG = ((com.quizlet.themes.b) c0814p.j(b)).b.g();
                long jE = ((com.quizlet.themes.b) c0814p.j(b)).b.e();
                i4 = i10 & (-33488897);
                qVar3 = nVar;
                j4 = ((com.quizlet.themes.b) c0814p.j(b)).k;
                i5 = AbstractC3205m5.g(c0814p).a;
                j5 = jE;
                i6 = 1;
                j6 = jG;
            } else {
                c0814p.Q();
                j6 = j;
                j5 = j2;
                j4 = j3;
                i6 = i;
                i5 = i2;
                i4 = i10 & (-33488897);
                qVar3 = qVar;
            }
            c0814p.q();
            float fA = 1 - ((androidx.compose.material3.X4) hVar.a).a();
            kotlin.jvm.internal.G g = new kotlin.jvm.internal.G();
            if (((androidx.compose.material3.X4) hVar.a).a() >= 0.97f) {
                g.a = 1.0f;
            }
            int i11 = i4 >> 3;
            androidx.compose.ui.layout.K kE = AbstractC0409s.e(androidx.compose.ui.b.h, false);
            int i12 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, qVar3);
            InterfaceC0915k.D0.getClass();
            C0913i c0913i = C0914j.b;
            c0814p.b0();
            androidx.compose.ui.q qVar6 = qVar3;
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0776c.E(c0814p, kE, C0914j.f);
            C0776c.E(c0814p, interfaceC0803j0L, C0914j.e);
            C0912h c0912h = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i12))) {
                android.support.v4.media.session.a.z(i12, c0814p, i12, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            androidx.compose.runtime.internal.d dVarE = androidx.compose.runtime.internal.e.e(-556467947, new com.quizlet.assembly.compose.listitems.h(g, title, i6), c0814p);
            androidx.compose.runtime.internal.d dVarE2 = androidx.compose.runtime.internal.e.e(1226862581, new com.quizlet.assembly.compose.toolbars.b(bVar, function0, 0), c0814p);
            androidx.compose.material3.V4 v4C = androidx.compose.material3.W4.c(j6, j6, j4, j5, c0814p, 16);
            long j10 = j4;
            long j11 = j5;
            long j12 = j6;
            Set set = androidx.compose.material3.windowsizeclass.c.b;
            int i13 = AbstractC0382e.g;
            if (i5 == 0) {
                c0814p.X(-970478276);
                c0814p.X(-1784204838);
                C0416v0 c0416v0B = androidx.compose.material3.W4.b(c0814p);
                WeakHashMap weakHashMap = androidx.compose.foundation.layout.S0.w;
                C0374a c0374a = new C0374a(c0416v0B, new C0416v0(C0380d.e(c0814p).k, i13));
                c0814p.p(false);
                qVar4 = qVar6;
                i7 = i6;
                androidx.compose.material3.D.c(dVarE, null, dVarE2, null, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, c0374a, v4C, hVar, c0814p, (i11 & 234881024) | 390);
                c0814p.p(false);
                f = fA;
            } else {
                qVar4 = qVar6;
                i7 = i6;
                c0814p.X(-970189635);
                c0814p.X(-1784204838);
                C0416v0 c0416v0B2 = androidx.compose.material3.W4.b(c0814p);
                WeakHashMap weakHashMap2 = androidx.compose.foundation.layout.S0.w;
                C0374a c0374a2 = new C0374a(c0416v0B2, new C0416v0(C0380d.e(c0814p).k, i13));
                c0814p.p(false);
                f = fA;
                androidx.compose.material3.D.b(dVarE, null, dVarE2, null, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, c0374a2, v4C, hVar, c0814p, (i11 & 234881024) | 390, 58);
                c0814p.p(false);
            }
            androidx.compose.material3.Q4.b(title, androidx.compose.ui.draw.g.a(qVar2, f), 0L, 0L, null, 0L, null, 0L, 0, false, 0, 0, null, ((com.quizlet.themes.f) c0814p.j(com.quizlet.themes.w.a)).h(), c0814p, i4 & 14, 0, 65532);
            c0814p = c0814p;
            c0814p.p(true);
            j7 = j12;
            j8 = j11;
            i8 = i5;
            qVar5 = qVar4;
            j9 = j10;
            i9 = i7;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new Function2(title, qVar5, qVar2, bVar, function0, j7, j8, j9, i9, hVar, i8, i3) { // from class: com.quizlet.assembly.compose.toolbars.a
                public final /* synthetic */ String a;
                public final /* synthetic */ q b;
                public final /* synthetic */ q c;
                public final /* synthetic */ androidx.compose.ui.graphics.painter.b d;
                public final /* synthetic */ Function0 e;
                public final /* synthetic */ long f;
                public final /* synthetic */ long g;
                public final /* synthetic */ long h;
                public final /* synthetic */ int i;
                public final /* synthetic */ com.quizlet.data.repository.achievements.h j;
                public final /* synthetic */ int k;

                @Override // kotlin.jvm.functions.Function2
                public final Object invoke(Object obj, Object obj2) {
                    ((Integer) obj2).getClass();
                    int iH = C0776c.H(1);
                    com.quizlet.data.repository.achievements.h hVar2 = this.j;
                    int i14 = this.k;
                    AbstractC3675m6.a(this.a, this.b, this.c, this.d, this.e, this.f, this.g, this.h, this.i, hVar2, i14, (InterfaceC0806l) obj, iH);
                    return Unit.a;
                }
            };
        }
    }

    public static Intent b(Context context, int i, StudyableModelData studyableModelData, String itemTitle, long j, boolean z, int i2, List list, InterfaceC4176w0 meteredEvent, boolean z2) {
        com.quizlet.generated.enums.A1 a1;
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(studyableModelData, "studyableModelData");
        Intrinsics.checkNotNullParameter(itemTitle, "itemTitle");
        Intrinsics.checkNotNullParameter(meteredEvent, "meteredEvent");
        if (i2 == 0) {
            a1 = com.quizlet.generated.enums.A1.LEARNING_ASSISTANT;
        } else {
            if (i2 != 1) {
                throw new IllegalArgumentException(android.support.v4.media.session.a.f(i2, "Invalid AssistantBehavior: "));
            }
            a1 = com.quizlet.generated.enums.A1.MOBILE_WRITE;
        }
        Intent intent = new Intent(context, (Class<?>) LearningAssistantActivity.class);
        AbstractC3266t5.c(intent, Integer.valueOf(i), studyableModelData, Long.valueOf(j), z, LearningAssistantActivity.D, a1.a(), list, null, 768);
        Bundle bundle = new Bundle();
        bundle.putInt("learnModeBehavior", i2);
        bundle.putString("studyableModelTitle", itemTitle);
        bundle.putSerializable("meteredEvent", meteredEvent);
        bundle.putBoolean("SHOW_ONBOARDING_KEY", z2);
        intent.putExtras(bundle);
        return intent;
    }
}

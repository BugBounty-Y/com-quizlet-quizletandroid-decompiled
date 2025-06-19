package com.quizlet.quizletandroid.ui.startpage.nav2.viewholder;

import android.content.Context;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.material3.Q4;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.platform.AndroidCompositionLocals_androidKt;
import androidx.compose.ui.platform.ComposeView;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3603d6;
import com.quizlet.quizletandroid.ui.startpage.nav2.model.O;
import com.quizlet.quizletandroid.ui.startpage.nav2.model.P;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class f extends com.quizlet.baserecyclerview.c {
    public static final int e;
    public final ComposeView d;

    static {
        g gVar = new g();
        int i = ComposeView.c;
        e = gVar.hashCode();
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public f(ComposeView composeView) {
        super(composeView);
        Intrinsics.checkNotNullParameter(composeView, "composeView");
        this.d = composeView;
    }

    @Override // com.quizlet.baserecyclerview.c
    public final void c(Object obj) {
        O item = (O) obj;
        Intrinsics.checkNotNullParameter(item, "item");
    }

    @Override // com.quizlet.baserecyclerview.c
    public final androidx.viewbinding.a d() {
        return new com.quizlet.explanations.myexplanations.ui.recyclerview.c(this, 22);
    }

    public final void f(O o, InterfaceC0806l interfaceC0806l, int i) {
        String string;
        C0814p c0814p;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(481875787);
        if ((((c0814p2.f(o) ? 4 : 2) | i | (c0814p2.h(this) ? 32 : 16)) & 19) == 18 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            Context context = (Context) c0814p2.j(AndroidCompositionLocals_androidKt.b);
            P p = o.d;
            if (p == P.d) {
                AbstractC3603d6 abstractC3603d6 = o.e;
                if (abstractC3603d6 == null) {
                    throw new IllegalArgumentException("source value can't be null if the set is recommended");
                }
                string = context.getString(p.a(abstractC3603d6), abstractC3603d6.c());
                Intrinsics.checkNotNullExpressionValue(string, "getString(...)");
            } else {
                string = context.getString(p.a(null));
                Intrinsics.d(string);
            }
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            mVar.s();
            float f = com.quizlet.ui.resources.designsystem.generated.j.h;
            mVar.s();
            mVar.q();
            float f2 = com.quizlet.ui.resources.designsystem.generated.j.i;
            mVar.s();
            c0814p = c0814p2;
            Q4.b(string, AbstractC0382e.x(nVar, f, f2, f, f), ((com.quizlet.themes.b) c0814p2.j(com.quizlet.themes.g.a)).b.e(), 0L, null, 0L, null, 0L, 0, false, 1, 0, null, ((com.quizlet.themes.f) c0814p2.j(com.quizlet.themes.w.a)).i, c0814p, 0, 3072, 57336);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.questionnaire.screens.d(this, o, i, 22);
        }
    }

    public final void g(O sectionHeader) {
        Intrinsics.checkNotNullParameter(sectionHeader, "sectionHeader");
        this.d.setContent(new androidx.compose.runtime.internal.d(true, -760074335, new e(this, sectionHeader, 1)));
    }
}

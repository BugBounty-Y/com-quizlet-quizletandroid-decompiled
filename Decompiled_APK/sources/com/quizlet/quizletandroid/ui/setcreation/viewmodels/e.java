package com.quizlet.quizletandroid.ui.setcreation.viewmodels;

import androidx.lifecycle.X;
import androidx.lifecycle.Y;
import androidx.lifecycle.p0;
import com.google.android.gms.internal.mlkit_common.u;
import io.reactivex.rxjava3.core.p;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.E;

@Metadata
/* loaded from: classes3.dex */
public final class e extends com.quizlet.viewmodel.b {
    public final u c;
    public final androidx.work.impl.model.c d;
    public final com.quizlet.db.a e;
    public final com.quizlet.quizletandroid.ui.setcreation.managers.b f;
    public final com.quizlet.local.ormlite.models.term.b g;
    public final X h;
    public final X i;
    public final Y j;
    public final Y k;
    public final X l;
    public final Y m;
    public final X n;
    public final X o;

    public e(u richTextFeature, androidx.work.impl.model.c userProperties, com.quizlet.db.a u13FeatureLossSharedPrefFeature, com.quizlet.quizletandroid.ui.setcreation.managers.b createSetHelper, com.quizlet.local.ormlite.models.term.b eventLogger) {
        Intrinsics.checkNotNullParameter(richTextFeature, "richTextFeature");
        Intrinsics.checkNotNullParameter(userProperties, "userProperties");
        Intrinsics.checkNotNullParameter(u13FeatureLossSharedPrefFeature, "u13FeatureLossSharedPrefFeature");
        Intrinsics.checkNotNullParameter(createSetHelper, "createSetHelper");
        Intrinsics.checkNotNullParameter(eventLogger, "eventLogger");
        this.c = richTextFeature;
        this.d = userProperties;
        this.e = u13FeatureLossSharedPrefFeature;
        this.f = createSetHelper;
        this.g = eventLogger;
        this.h = new X(1);
        X x = new X(0);
        this.i = x;
        Y y = new Y();
        this.j = y;
        Y y2 = new Y();
        this.k = y2;
        this.l = new X(1);
        this.m = new Y();
        this.n = new X(1);
        this.o = new X(1);
        final int i = 0;
        x.m(y, new com.quizlet.explanations.feedback.ui.fragments.c(17, new Function1(this) { // from class: com.quizlet.quizletandroid.ui.setcreation.viewmodels.a
            public final /* synthetic */ e b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function1
            public final Object invoke(Object obj) {
                switch (i) {
                    case 0:
                        this.b.B();
                        break;
                    default:
                        this.b.B();
                        break;
                }
                return Unit.a;
            }
        }));
        final int i2 = 1;
        x.m(y2, new com.quizlet.explanations.feedback.ui.fragments.c(17, new Function1(this) { // from class: com.quizlet.quizletandroid.ui.setcreation.viewmodels.a
            public final /* synthetic */ e b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function1
            public final Object invoke(Object obj) {
                switch (i2) {
                    case 0:
                        this.b.B();
                        break;
                    default:
                        this.b.B();
                        break;
                }
                return Unit.a;
            }
        }));
        C();
        io.reactivex.rxjava3.internal.operators.single.g gVarU = userProperties.u();
        io.reactivex.rxjava3.internal.operators.flowable.b bVarF = p.f(Boolean.valueOf(u13FeatureLossSharedPrefFeature.a.getBoolean("check_in_switch_prompt_tooltip", false)));
        Intrinsics.checkNotNullExpressionValue(bVarF, "just(...)");
        io.reactivex.rxjava3.internal.observers.e eVarI = p.p(gVarU, bVarF, c.a).i(new d(this, 0), io.reactivex.rxjava3.internal.functions.d.e);
        Intrinsics.checkNotNullExpressionValue(eVarI, "subscribe(...)");
        Intrinsics.checkNotNullParameter(eVarI, "<this>");
        A(eVarI);
        E.A(p0.j(this), null, null, new b(this, null), 3);
    }

    public final void B() {
        io.reactivex.rxjava3.internal.observers.e eVarI = this.d.u().i(new d(this, 1), io.reactivex.rxjava3.internal.functions.d.e);
        Intrinsics.checkNotNullExpressionValue(eVarI, "subscribe(...)");
        Intrinsics.checkNotNullParameter(eVarI, "<this>");
        A(eVarI);
    }

    public final void C() {
        io.reactivex.rxjava3.internal.observers.e eVarI = this.c.k(this.d).i(new d(this, 2), io.reactivex.rxjava3.internal.functions.d.e);
        Intrinsics.checkNotNullExpressionValue(eVarI, "subscribe(...)");
        Intrinsics.checkNotNullParameter(eVarI, "<this>");
        A(eVarI);
    }
}

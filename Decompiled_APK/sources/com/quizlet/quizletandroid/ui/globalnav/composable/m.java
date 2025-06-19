package com.quizlet.quizletandroid.ui.globalnav.composable;

import androidx.fragment.app.AbstractC1136h0;
import androidx.fragment.app.I;
import androidx.glance.appwidget.protobuf.Z;
import androidx.navigation.H;
import com.google.android.gms.internal.mlkit_vision_document_scanner.E4;
import com.quizlet.data.model.EnumC4164s0;
import com.quizlet.quizletandroid.ui.globalnav.data.GlobalNavSuiteItem$FreeTrial;
import com.quizlet.quizletandroid.ui.globalnav.data.GlobalNavSuiteItem$Home;
import com.quizlet.quizletandroid.ui.globalnav.data.GlobalNavSuiteItem$YourLibrary;
import com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.A;
import com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.B;
import com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.C;
import com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.C4740i;
import com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.C4743l;
import com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.C4744m;
import com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.C4746o;
import com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.C4747p;
import com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.C4748q;
import com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.C4749s;
import com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.C4750t;
import com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.D;
import com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.O;
import com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.P;
import com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.Q;
import com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.S;
import com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.T;
import com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.y;
import com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.z;
import com.quizlet.upgrade.ui.fragment.FreeTrialConfirmationFragment;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class m extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public /* synthetic */ Object j;
    public final /* synthetic */ H k;
    public final /* synthetic */ com.quizlet.quizletandroid.ui.globalnav.navigation.a l;
    public final /* synthetic */ I m;
    public final /* synthetic */ androidx.activity.compose.o n;
    public final /* synthetic */ androidx.activity.compose.o o;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public m(H h, com.quizlet.quizletandroid.ui.globalnav.navigation.a aVar, I i, androidx.activity.compose.o oVar, androidx.activity.compose.o oVar2, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = h;
        this.l = aVar;
        this.m = i;
        this.n = oVar;
        this.o = oVar2;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        m mVar = new m(this.k, this.l, this.m, this.n, this.o, hVar);
        mVar.j = obj;
        return mVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((m) create((D) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        D d = (D) this.j;
        boolean zB = Intrinsics.b(d, C4740i.a);
        com.quizlet.quizletandroid.ui.globalnav.navigation.a aVar2 = this.l;
        if (zB) {
            aVar2.e();
        } else if (d instanceof C4743l) {
            aVar2.F(((C4743l) d).a);
        } else if (d instanceof C4744m) {
            aVar2.v(((C4744m) d).a);
        } else {
            boolean zB2 = Intrinsics.b(d, C4746o.a);
            H h = this.k;
            if (zB2) {
                E4.g(h, GlobalNavSuiteItem$Home.INSTANCE);
            } else if (d instanceof C4747p) {
                EnumC4164s0 enumC4164s0 = ((C4747p) d).a;
                E4.g(h, new GlobalNavSuiteItem$YourLibrary(enumC4164s0 != null ? enumC4164s0.name() : null));
            } else if (d instanceof C4748q) {
                aVar2.n(((C4748q) d).a);
            } else if (Intrinsics.b(d, com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.r.a)) {
                aVar2.c(this.n);
            } else if (Intrinsics.b(d, C4749s.a)) {
                aVar2.H();
            } else if (d instanceof C4750t) {
                aVar2.y(((C4750t) d).a);
            } else if (d instanceof com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.u) {
                aVar2.E(((com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.u) d).a);
            } else if (Intrinsics.b(d, com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.v.a)) {
                aVar2.G();
            } else if (d instanceof com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.w) {
                aVar2.b(((com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.w) d).a);
            } else if (d instanceof y) {
                aVar2.l(((y) d).a);
            } else if (d instanceof z) {
                aVar2.A(((z) d).a);
            } else if (d instanceof A) {
                ((A) d).getClass();
                com.quizlet.quizletandroid.ui.startpage.nav2.model.v vVar = com.quizlet.quizletandroid.ui.startpage.nav2.model.v.a;
                E4.g(h, new GlobalNavSuiteItem$FreeTrial("DEEP_LINK", "DeepLink"));
            } else if (Intrinsics.b(d, B.a)) {
                aVar2.w();
            } else if (Intrinsics.b(d, C.a)) {
                aVar2.m();
            } else if (d instanceof T) {
                aVar2.D(((T) d).a);
            } else if (d instanceof com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.x) {
                aVar2.B(this.o, ((com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.x) d).a);
            } else {
                boolean z = d instanceof Q;
                I i = this.m;
                if (z) {
                    AbstractC1136h0 supportFragmentManager = i.getSupportFragmentManager();
                    Intrinsics.checkNotNullExpressionValue(supportFragmentManager, "getSupportFragmentManager(...)");
                    ((Q) d).getClass();
                    aVar2.f(supportFragmentManager, true);
                } else if (Intrinsics.b(d, S.a)) {
                    AbstractC1136h0 supportFragmentManager2 = i.getSupportFragmentManager();
                    Intrinsics.checkNotNullExpressionValue(supportFragmentManager2, "getSupportFragmentManager(...)");
                    aVar2.a(supportFragmentManager2);
                } else if (Intrinsics.b(d, P.a)) {
                    AbstractC1136h0 fragmentManager = i.getSupportFragmentManager();
                    Intrinsics.checkNotNullExpressionValue(fragmentManager, "getSupportFragmentManager(...)");
                    aVar2.getClass();
                    Intrinsics.checkNotNullParameter(fragmentManager, "fragmentManager");
                    Intrinsics.checkNotNullParameter(fragmentManager, "fragmentManager");
                    if (fragmentManager.E("FreeTrialConfirmationFragment") == null) {
                        new FreeTrialConfirmationFragment().O(fragmentManager, "FreeTrialConfirmationFragment");
                    }
                } else {
                    if (!Intrinsics.b(d, O.a)) {
                        throw new NoWhenBranchMatchedException();
                    }
                    AbstractC1136h0 fragmentManager2 = i.getSupportFragmentManager();
                    Intrinsics.checkNotNullExpressionValue(fragmentManager2, "getSupportFragmentManager(...)");
                    aVar2.getClass();
                    Intrinsics.checkNotNullParameter(fragmentManager2, "fragmentManager");
                    Intrinsics.checkNotNullParameter(fragmentManager2, "fragmentManager");
                    if (!fragmentManager2.R()) {
                        new com.features.flashcards.creatormarketing.f().O(fragmentManager2, com.features.flashcards.creatormarketing.f.x);
                    }
                }
            }
        }
        return Unit.a;
    }
}

package com.quizlet.quizletandroid.ui.globalnav.composable;

import android.content.Context;
import androidx.fragment.app.AbstractC1136h0;
import androidx.fragment.app.I;
import androidx.glance.appwidget.protobuf.Z;
import androidx.navigation.H;
import com.google.android.gms.internal.mlkit_vision_common.M3;
import com.quizlet.data.model.m2;
import com.quizlet.features.universaluploadflow.UniversalUploadFlowActivity;
import com.quizlet.quizletandroid.ui.startpage.nav2.model.C4710f;
import com.quizlet.quizletandroid.ui.startpage.nav2.model.C4711g;
import com.quizlet.quizletandroid.ui.startpage.nav2.model.C4712h;
import com.quizlet.quizletandroid.ui.startpage.nav2.model.C4713i;
import com.quizlet.quizletandroid.ui.startpage.nav2.model.C4714j;
import com.quizlet.quizletandroid.ui.startpage.nav2.model.InterfaceC4715k;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class h extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public /* synthetic */ Object j;
    public final /* synthetic */ H k;
    public final /* synthetic */ com.quizlet.quizletandroid.ui.globalnav.navigation.a l;
    public final /* synthetic */ I m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public h(H h, com.quizlet.quizletandroid.ui.globalnav.navigation.a aVar, I i, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = h;
        this.l = aVar;
        this.m = i;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        h hVar2 = new h(this.k, this.l, this.m, hVar);
        hVar2.j = obj;
        return hVar2;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((h) create((InterfaceC4715k) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        InterfaceC4715k interfaceC4715k = (InterfaceC4715k) this.j;
        this.k.f();
        boolean zB = Intrinsics.b(interfaceC4715k, C4710f.a);
        com.quizlet.quizletandroid.ui.globalnav.navigation.a aVar2 = this.l;
        if (zB) {
            aVar2.s();
        } else if (Intrinsics.b(interfaceC4715k, C4711g.a)) {
            AbstractC1136h0 supportFragmentManager = this.m.getSupportFragmentManager();
            Intrinsics.checkNotNullExpressionValue(supportFragmentManager, "getSupportFragmentManager(...)");
            aVar2.u(supportFragmentManager);
        } else if (Intrinsics.b(interfaceC4715k, C4713i.a)) {
            aVar2.w();
        } else if (Intrinsics.b(interfaceC4715k, C4714j.a)) {
            aVar2.G();
        } else {
            if (!Intrinsics.b(interfaceC4715k, C4712h.a)) {
                throw new NoWhenBranchMatchedException();
            }
            com.quizlet.features.universaluploadflow.navigation.d dVar = aVar2.u;
            int i = UniversalUploadFlowActivity.h;
            m2 m2Var = m2.c;
            Context context = dVar.a;
            context.startActivity(M3.a(context, m2Var));
        }
        return Unit.a;
    }
}

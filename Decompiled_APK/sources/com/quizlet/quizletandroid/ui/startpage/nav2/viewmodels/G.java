package com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels;

import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.AbstractC5040y;

/* loaded from: classes3.dex */
public final class G extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ L k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public G(L l, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = l;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new G(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((G) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) throws Throwable {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        L l = this.k;
        if (i == 0) {
            Z.e(obj);
            com.google.android.gms.measurement.internal.J j = l.n;
            this.j = 1;
            j.getClass();
            obj = kotlinx.coroutines.E.J((AbstractC5040y) j.c, new com.quizlet.features.onboarding.ell.q(j, null), this);
            if (obj == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
        }
        if (((Boolean) obj).booleanValue()) {
            l.p.h(S.a);
        } else {
            l.p.h(r.a);
        }
        return Unit.a;
    }
}

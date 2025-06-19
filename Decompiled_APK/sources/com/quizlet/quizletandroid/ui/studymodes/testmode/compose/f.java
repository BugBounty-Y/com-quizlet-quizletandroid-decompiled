package com.quizlet.quizletandroid.ui.studymodes.testmode.compose;

import androidx.glance.appwidget.protobuf.Z;
import androidx.lifecycle.C1258t;
import androidx.lifecycle.Y;
import com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels.G;
import com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels.t;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C;
import kotlinx.coroutines.flow.InterfaceC4992i;
import kotlinx.coroutines.flow.e0;

/* loaded from: classes3.dex */
public final class f extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ G k;
    public final /* synthetic */ t l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public f(t tVar, G g, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = g;
        this.l = tVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new f(this.l, this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((f) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            Y y = this.k.z;
            Intrinsics.checkNotNullParameter(y, "<this>");
            InterfaceC4992i interfaceC4992iF = e0.f(e0.g(new C1258t(y, null)), -1);
            e eVar = new e(this.l, null);
            this.j = 1;
            if (e0.i(interfaceC4992iF, eVar, this) == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
        }
        return Unit.a;
    }
}

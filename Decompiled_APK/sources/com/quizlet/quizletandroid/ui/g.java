package com.quizlet.quizletandroid.ui;

import androidx.camera.camera2.internal.c0;
import androidx.compose.material3.internal.H;
import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.local.datastore.preferences.C4567d;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;
import kotlinx.coroutines.flow.e0;

/* loaded from: classes3.dex */
public final class g extends i implements Function2 {
    public int j;
    public final /* synthetic */ c0 k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public g(c0 c0Var, h hVar) {
        super(2, hVar);
        this.k = c0Var;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        return new g(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((g) create((C) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            com.lyft.android.scissors.b bVar = (com.lyft.android.scissors.b) this.k.e;
            this.j = 1;
            C4567d c4567d = (C4567d) bVar.b;
            obj = e0.r(new H(5, c4567d.a.getData(), c4567d), this);
            if (obj == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
        }
        return Boolean.valueOf(obj != null);
    }
}

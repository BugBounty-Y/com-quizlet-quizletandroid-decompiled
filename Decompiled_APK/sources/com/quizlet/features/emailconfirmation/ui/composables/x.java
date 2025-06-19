package com.quizlet.features.emailconfirmation.ui.composables;

import android.content.Context;
import androidx.compose.material3.O3;
import androidx.glance.appwidget.protobuf.Z;
import com.google.android.gms.internal.mlkit_vision_barcode.V;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes2.dex */
public final class x extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public /* synthetic */ boolean k;
    public final /* synthetic */ O3 l;
    public final /* synthetic */ Context m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public x(O3 o3, Context context, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = o3;
        this.m = context;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        x xVar = new x(this.l, this.m, hVar);
        xVar.k = ((Boolean) obj).booleanValue();
        return xVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        Boolean bool = (Boolean) obj;
        bool.booleanValue();
        return ((x) create(bool, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            boolean z = this.k;
            this.j = 1;
            if (V.d(this.l, z, this.m, this) == aVar) {
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

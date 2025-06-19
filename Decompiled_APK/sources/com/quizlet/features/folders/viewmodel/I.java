package com.quizlet.features.folders.viewmodel;

import androidx.glance.appwidget.protobuf.Z;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3409x1;
import com.quizlet.features.folders.data.S0;
import com.quizlet.features.folders.data.T0;
import java.util.ArrayList;
import kotlin.Unit;

/* loaded from: classes3.dex */
public final class I extends kotlin.coroutines.jvm.internal.i implements kotlin.jvm.functions.c {
    public /* synthetic */ boolean j;
    public /* synthetic */ S0 k;

    @Override // kotlin.jvm.functions.c
    public final Object invoke(Object obj, Object obj2, Object obj3) {
        boolean zBooleanValue = ((Boolean) obj).booleanValue();
        I i = new I(3, (kotlin.coroutines.h) obj3);
        i.j = zBooleanValue;
        i.k = (S0) obj2;
        return i.invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        boolean z = this.j;
        S0 s0 = this.k;
        ArrayList arrayList = new ArrayList();
        if (s0.b) {
            arrayList.add(com.quizlet.features.infra.folder.study.data.a.a);
        }
        return new T0(AbstractC3409x1.i(arrayList), z && s0.a);
    }
}

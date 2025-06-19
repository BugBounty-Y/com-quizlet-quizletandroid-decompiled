package com.quizlet.upgrade.data;

import androidx.glance.appwidget.protobuf.Z;
import java.util.ArrayList;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: com.quizlet.upgrade.data.e, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4837e extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public ArrayList j;
    public int k;
    public final /* synthetic */ com.quizlet.data.repository.user.a l;
    public final /* synthetic */ boolean m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C4837e(com.quizlet.data.repository.user.a aVar, boolean z, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = aVar;
        this.m = z;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new C4837e(this.l, this.m, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C4837e) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.k;
        if (i != 0) {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            ArrayList arrayList = this.j;
            Z.e(obj);
            return arrayList;
        }
        Z.e(obj);
        ArrayList arrayList2 = new ArrayList();
        C4836d c4836d = new C4836d(arrayList2, null);
        this.j = arrayList2;
        this.k = 1;
        return com.quizlet.data.repository.user.a.d(this.l, this.m, c4836d, this) == aVar ? aVar : arrayList2;
    }
}

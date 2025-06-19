package com.quizlet.remote.model.union.studysetwithcreatorinclass;

import androidx.glance.appwidget.protobuf.Z;
import com.google.android.gms.internal.mlkit_vision_barcode.U;
import com.quizlet.remote.service.InterfaceC4779f;
import java.util.List;
import kotlin.Unit;
import kotlin.collections.A;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;

/* loaded from: classes3.dex */
public final class c extends i implements kotlin.jvm.functions.c {
    public int j;
    public /* synthetic */ int k;
    public /* synthetic */ String l;
    public final /* synthetic */ e m;
    public final /* synthetic */ long n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public c(e eVar, long j, h hVar) {
        super(3, hVar);
        this.m = eVar;
        this.n = j;
    }

    @Override // kotlin.jvm.functions.c
    public final Object invoke(Object obj, Object obj2, Object obj3) {
        int iIntValue = ((Number) obj).intValue();
        c cVar = new c(this.m, this.n, (h) obj3);
        cVar.k = iIntValue;
        cVar.l = (String) obj2;
        return cVar.invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i != 0) {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
            return obj;
        }
        Z.e(obj);
        int i2 = this.k;
        String str = this.l;
        com.quizlet.quizletandroid.ui.login.h hVar = this.m.a;
        List listB = A.b(new Long(this.n));
        this.j = 1;
        Object objB = ((InterfaceC4779f) hVar.b).b(U.c(listB), i2, str, this);
        return objB == aVar ? aVar : objB;
    }
}

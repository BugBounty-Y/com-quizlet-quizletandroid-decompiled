package com.quizlet.remote.model.union.studysetwithcreatorinclass;

import androidx.glance.appwidget.protobuf.Z;
import com.google.android.gms.internal.mlkit_vision_barcode.U;
import com.quizlet.remote.service.InterfaceC4779f;
import java.util.List;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;

/* loaded from: classes3.dex */
public final class a extends i implements kotlin.jvm.functions.c {
    public int j;
    public /* synthetic */ int k;
    public /* synthetic */ String l;
    public final /* synthetic */ e m;
    public final /* synthetic */ List n;
    public final /* synthetic */ boolean o;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public a(e eVar, List list, boolean z, h hVar) {
        super(3, hVar);
        this.m = eVar;
        this.n = list;
        this.o = z;
    }

    @Override // kotlin.jvm.functions.c
    public final Object invoke(Object obj, Object obj2, Object obj3) {
        int iIntValue = ((Number) obj).intValue();
        a aVar = new a(this.m, this.n, this.o, (h) obj3);
        aVar.k = iIntValue;
        aVar.l = (String) obj2;
        return aVar.invokeSuspend(Unit.a);
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
        this.j = 1;
        String strC = U.c(this.n);
        InterfaceC4779f interfaceC4779f = (InterfaceC4779f) hVar.b;
        Object objA = this.o ? interfaceC4779f.a(strC, i2, str, this) : interfaceC4779f.c(strC, i2, str, this);
        return objA == aVar ? aVar : objA;
    }
}

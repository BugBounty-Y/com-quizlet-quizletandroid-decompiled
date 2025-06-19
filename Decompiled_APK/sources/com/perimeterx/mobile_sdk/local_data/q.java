package com.perimeterx.mobile_sdk.local_data;

import android.app.Application;
import androidx.glance.appwidget.protobuf.Z;
import com.google.android.gms.internal.mlkit_vision_barcode.S6;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes2.dex */
public final class q extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ v k;
    public final /* synthetic */ x l;
    public final /* synthetic */ String m;
    public final /* synthetic */ int n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public q(v vVar, x xVar, String str, int i, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = vVar;
        this.l = xVar;
        this.m = str;
        this.n = i;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new q(this.k, this.l, this.m, this.n, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((q) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        Object obj2 = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            v vVar = this.k;
            Application application = vVar.a;
            String strH = v.h(vVar, this.l.a(), this.m);
            this.j = 1;
            Object objD = S6.d(vVar.g(application), new t(strH, this.n, null), this);
            if (objD != obj2) {
                objD = Unit.a;
            }
            if (objD == obj2) {
                return obj2;
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

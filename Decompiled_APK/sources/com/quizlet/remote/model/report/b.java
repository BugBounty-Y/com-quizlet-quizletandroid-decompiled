package com.quizlet.remote.model.report;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.remote.service.w;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlin.p;
import kotlin.r;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class b extends i implements Function2 {
    public int j;
    public final /* synthetic */ c k;
    public final /* synthetic */ int l;
    public final /* synthetic */ int m;
    public final /* synthetic */ String n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b(c cVar, int i, int i2, String str, h hVar) {
        super(2, hVar);
        this.k = cVar;
        this.l = i;
        this.m = i2;
        this.n = str;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        return new b(this.k, this.l, this.m, this.n, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((b) create((C) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        Object objB;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        try {
            if (i == 0) {
                Z.e(obj);
                w wVar = (w) this.k.a;
                int i2 = this.l;
                int i3 = this.m;
                String str = this.n;
                this.j = 1;
                if (wVar.a(i2, i3, str, this) == aVar) {
                    return aVar;
                }
            } else {
                if (i != 1) {
                    throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                }
                Z.e(obj);
            }
            objB = Unit.a;
            p pVar = r.b;
        } catch (Exception e) {
            p pVar2 = r.b;
            objB = Z.b(e);
        }
        return new r(objB);
    }
}

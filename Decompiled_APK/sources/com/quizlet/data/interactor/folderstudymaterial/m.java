package com.quizlet.data.interactor.folderstudymaterial;

import androidx.datastore.core.InterfaceC1076h;
import androidx.glance.appwidget.protobuf.Z;
import com.google.android.gms.internal.mlkit_vision_barcode.S6;
import java.util.List;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes2.dex */
public final class m extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public long j;
    public int k;
    public /* synthetic */ Object l;
    public final /* synthetic */ o m;
    public final /* synthetic */ long n;
    public final /* synthetic */ List o;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public m(o oVar, long j, List list, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.m = oVar;
        this.n = j;
        this.o = list;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        m mVar = new m(this.m, this.n, this.o, hVar);
        mVar.l = obj;
        return mVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((m) create(new kotlin.r(((kotlin.r) obj).a), (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        o oVar;
        long j;
        Object obj2 = kotlin.coroutines.intrinsics.a.a;
        int i = this.k;
        if (i == 0) {
            Z.e(obj);
            Object obj3 = ((kotlin.r) this.l).a;
            if (obj3 instanceof kotlin.q) {
                obj3 = null;
            }
            List list = (List) obj3;
            if (list != null) {
                o oVar2 = this.m;
                long j2 = this.n;
                List list2 = this.o;
                try {
                    androidx.work.impl.model.e eVar = oVar2.b;
                    String strB = o.b(j2, list2);
                    this.l = oVar2;
                    this.j = j2;
                    this.k = 1;
                    Object objD = S6.d((InterfaceC1076h) eVar.c, new com.quizlet.local.cache.d(strB, eVar, list, null), this);
                    if (objD != obj2) {
                        objD = Unit.a;
                    }
                    if (objD == obj2) {
                        return obj2;
                    }
                } catch (Exception e) {
                    e = e;
                    oVar = oVar2;
                    j = j2;
                    oVar.c.j("Failed to cache study materials for folderId=" + j, e);
                    return Unit.a;
                }
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            j = this.j;
            oVar = (o) this.l;
            try {
                Z.e(obj);
            } catch (Exception e2) {
                e = e2;
                oVar.c.j("Failed to cache study materials for folderId=" + j, e);
                return Unit.a;
            }
        }
        return Unit.a;
    }
}

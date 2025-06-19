package com.quizlet.features.infra.folder.create.coursefolder.viewmodel;

import androidx.glance.appwidget.protobuf.Z;
import androidx.lifecycle.p0;
import com.quizlet.features.infra.folder.create.coursefolder.data.g;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;
import kotlinx.coroutines.E;

/* loaded from: classes3.dex */
public final class b extends i implements Function2 {
    public int j;
    public final /* synthetic */ e k;
    public final /* synthetic */ g l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b(e eVar, g gVar, h hVar) {
        super(2, hVar);
        this.k = eVar;
        this.l = gVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        return new b(this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((b) create((C) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        e eVar = this.k;
        g gVar = this.l;
        if (i == 0) {
            Z.e(obj);
            Long l = gVar.d;
            if (l == null) {
                l = new Long(0L);
            }
            eVar.j = l;
            eVar.i = gVar.a;
            eVar.n = gVar.b;
            this.j = 1;
            obj = eVar.d.d(this);
            if (obj == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
        }
        if (((Boolean) obj).booleanValue()) {
            com.quizlet.features.infra.folder.create.data.b bVar = gVar.b;
            com.quizlet.features.infra.folder.create.data.b bVar2 = com.quizlet.features.infra.folder.create.data.b.a;
            com.quizlet.features.infra.folder.create.data.i iVar = gVar.c;
            eVar.e = bVar == bVar2 || iVar != null;
            if (iVar != null) {
                eVar.l = iVar.a;
                eVar.m = iVar.c;
                eVar.f = true;
                String str = iVar.d;
                eVar.C(iVar.b, str != null ? str : "", true);
            } else {
                E.A(p0.j(eVar), null, null, new a(eVar, null), 3);
            }
        } else {
            eVar.C("", "", false);
        }
        return Unit.a;
    }
}

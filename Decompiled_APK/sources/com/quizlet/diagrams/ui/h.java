package com.quizlet.diagrams.ui;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.studiablemodels.diagrams.DiagramData;
import java.util.Arrays;
import java.util.LinkedHashSet;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.AbstractC5040y;
import kotlinx.coroutines.C;
import kotlinx.coroutines.E;
import kotlinx.coroutines.flow.s0;

/* loaded from: classes2.dex */
public final class h extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ i k;
    public final /* synthetic */ DiagramData l;
    public final /* synthetic */ com.quizlet.diagrams.b[] m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public h(i iVar, DiagramData diagramData, com.quizlet.diagrams.b[] bVarArr, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = iVar;
        this.l = diagramData;
        this.m = bVarArr;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new h(this.k, this.l, this.m, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((h) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) throws Throwable {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        i iVar = this.k;
        if (i == 0) {
            Z.e(obj);
            com.quizlet.data.repository.classfolder.e eVar = iVar.b;
            LinkedHashSet linkedHashSet = iVar.c;
            com.quizlet.diagrams.b[] bVarArr = this.m;
            com.quizlet.diagrams.b[] bVarArr2 = (com.quizlet.diagrams.b[]) Arrays.copyOf(bVarArr, bVarArr.length);
            this.j = 1;
            eVar.getClass();
            obj = E.J((AbstractC5040y) eVar.d, new a(eVar, this.l, linkedHashSet, bVarArr2, null), this);
            if (obj == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
        }
        s0 s0Var = iVar.d;
        j jVar = new j((String) obj);
        s0Var.getClass();
        s0Var.m(null, jVar);
        return Unit.a;
    }
}

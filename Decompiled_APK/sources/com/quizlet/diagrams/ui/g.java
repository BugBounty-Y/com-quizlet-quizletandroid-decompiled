package com.quizlet.diagrams.ui;

import androidx.lifecycle.InterfaceC1250k;
import androidx.lifecycle.J;
import androidx.lifecycle.p0;
import com.quizlet.studiablemodels.diagrams.DiagramData;
import java.util.Arrays;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.E;

/* loaded from: classes2.dex */
public final class g implements InterfaceC1250k {
    public final /* synthetic */ i a;
    public final /* synthetic */ DiagramData b;
    public final /* synthetic */ com.quizlet.diagrams.b[] c;

    public g(i iVar, DiagramData diagramData, com.quizlet.diagrams.b[] bVarArr) {
        this.a = iVar;
        this.b = diagramData;
        this.c = bVarArr;
    }

    @Override // androidx.lifecycle.InterfaceC1250k
    public final void onCreate(J owner) {
        Intrinsics.checkNotNullParameter(owner, "owner");
        Intrinsics.checkNotNullParameter(owner, "owner");
        com.quizlet.diagrams.b[] bVarArr = this.c;
        com.quizlet.diagrams.b[] diagramLoadingConfigurations = (com.quizlet.diagrams.b[]) Arrays.copyOf(bVarArr, bVarArr.length);
        i iVar = this.a;
        iVar.getClass();
        DiagramData data = this.b;
        Intrinsics.checkNotNullParameter(data, "data");
        Intrinsics.checkNotNullParameter(diagramLoadingConfigurations, "diagramLoadingConfigurations");
        E.A(p0.j(iVar), null, null, new h(iVar, data, diagramLoadingConfigurations, null), 3);
    }
}

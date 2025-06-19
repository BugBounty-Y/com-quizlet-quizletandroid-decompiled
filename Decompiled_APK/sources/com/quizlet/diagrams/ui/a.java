package com.quizlet.diagrams.ui;

import android.content.Context;
import androidx.compose.animation.d0;
import androidx.glance.appwidget.protobuf.Z;
import com.fasterxml.jackson.databind.ObjectWriter;
import com.quizlet.studiablemodels.diagrams.DiagramData;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.Iterator;
import java.util.LinkedHashSet;
import kotlin.Unit;
import kotlin.collections.C4933y;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C;

/* loaded from: classes2.dex */
public final class a extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public final /* synthetic */ com.quizlet.data.repository.classfolder.e j;
    public final /* synthetic */ DiagramData k;
    public final /* synthetic */ LinkedHashSet l;
    public final /* synthetic */ com.quizlet.diagrams.b[] m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public a(com.quizlet.data.repository.classfolder.e eVar, DiagramData diagramData, LinkedHashSet linkedHashSet, com.quizlet.diagrams.b[] bVarArr, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.j = eVar;
        this.k = diagramData;
        this.l = linkedHashSet;
        this.m = bVarArr;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new a(this.j, this.k, this.l, this.m, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((a) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) throws IOException {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        com.quizlet.data.repository.classfolder.e eVar = this.j;
        InputStream inputStreamOpen = ((Context) eVar.b).getAssets().open("diagrams/diagram.html");
        Intrinsics.checkNotNullExpressionValue(inputStreamOpen, "open(...)");
        String strB = com.fasterxml.uuid.b.b(inputStreamOpen);
        Intrinsics.d(strB);
        com.quizlet.diagrams.b[] bVarArr = this.m;
        com.quizlet.diagrams.b[] bVarArr2 = (com.quizlet.diagrams.b[]) Arrays.copyOf(bVarArr, bVarArr.length);
        StringBuilder sb = new StringBuilder();
        sb.append("init(%s);");
        Intrinsics.checkNotNullExpressionValue(sb, "append(...)");
        com.quizlet.diagrams.b[] bVarArr3 = (com.quizlet.diagrams.b[]) Arrays.copyOf(bVarArr2, bVarArr2.length);
        for (com.quizlet.diagrams.b bVar : bVarArr3) {
            sb.append(bVar.a);
        }
        if (!C4933y.u(com.quizlet.diagrams.b.c, bVarArr3)) {
            sb.append("showTerms();");
        }
        sb.append("renderDiagram();");
        StringBuilder sb2 = new StringBuilder();
        String string = sb.toString();
        Intrinsics.checkNotNullExpressionValue(string, "toString(...)");
        String strWriteValueAsString = ((ObjectWriter) eVar.c).writeValueAsString(this.k);
        Intrinsics.checkNotNullExpressionValue(strWriteValueAsString, "writeValueAsString(...)");
        String str = String.format(string, Arrays.copyOf(new Object[]{strWriteValueAsString}, 1));
        Intrinsics.checkNotNullExpressionValue(str, "format(...)");
        sb2.append(str);
        Intrinsics.checkNotNullExpressionValue(sb2, "append(...)");
        Iterator it2 = this.l.iterator();
        while (it2.hasNext()) {
            String str2 = String.format("onSelectTerm('%d');", Arrays.copyOf(new Object[]{Long.valueOf(((Number) it2.next()).longValue())}, 1));
            Intrinsics.checkNotNullExpressionValue(str2, "format(...)");
            sb2.append(str2);
        }
        String string2 = sb2.toString();
        Intrinsics.checkNotNullExpressionValue(string2, "toString(...)");
        return d0.s(new Object[]{string2}, 1, strB, "format(...)");
    }
}

package com.quizlet.features.folders.composables;

import android.os.Bundle;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.L0;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3206m6;
import com.quizlet.features.folders.data.C4271a0;
import com.quizlet.features.folders.data.C4273b0;
import com.quizlet.features.folders.data.C4275c0;
import com.quizlet.features.folders.data.C4277d0;
import com.quizlet.features.folders.data.C4279e0;
import com.quizlet.features.folders.data.C4281f0;
import com.quizlet.features.folders.data.C4283g0;
import com.quizlet.features.folders.data.C4285h0;
import com.quizlet.features.folders.data.C4287i0;
import com.quizlet.features.folders.data.InterfaceC4289j0;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Pair;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class A extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public /* synthetic */ Object j;
    public final /* synthetic */ com.quizlet.features.folders.navigation.b k;
    public final /* synthetic */ com.quizlet.assembly.compose.modals.x l;
    public final /* synthetic */ com.quizlet.assembly.compose.modals.x m;
    public final /* synthetic */ com.quizlet.assembly.compose.modals.x n;
    public final /* synthetic */ com.quizlet.assembly.compose.modals.x o;
    public final /* synthetic */ com.quizlet.assembly.compose.modals.x p;
    public final /* synthetic */ com.quizlet.assembly.compose.modals.x q;
    public final /* synthetic */ com.quizlet.assembly.compose.modals.x r;
    public final /* synthetic */ com.quizlet.assembly.compose.modals.x s;
    public final /* synthetic */ com.quizlet.assembly.compose.modals.x t;
    public final /* synthetic */ com.quizlet.assembly.compose.modals.x u;
    public final /* synthetic */ com.quizlet.assembly.compose.modals.x v;
    public final /* synthetic */ InterfaceC0773a0 w;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public A(com.quizlet.features.folders.navigation.b bVar, com.quizlet.assembly.compose.modals.x xVar, com.quizlet.assembly.compose.modals.x xVar2, com.quizlet.assembly.compose.modals.x xVar3, com.quizlet.assembly.compose.modals.x xVar4, com.quizlet.assembly.compose.modals.x xVar5, com.quizlet.assembly.compose.modals.x xVar6, com.quizlet.assembly.compose.modals.x xVar7, com.quizlet.assembly.compose.modals.x xVar8, com.quizlet.assembly.compose.modals.x xVar9, com.quizlet.assembly.compose.modals.x xVar10, com.quizlet.assembly.compose.modals.x xVar11, InterfaceC0773a0 interfaceC0773a0, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = bVar;
        this.l = xVar;
        this.m = xVar2;
        this.n = xVar3;
        this.o = xVar4;
        this.p = xVar5;
        this.q = xVar6;
        this.r = xVar7;
        this.s = xVar8;
        this.t = xVar9;
        this.u = xVar10;
        this.v = xVar11;
        this.w = interfaceC0773a0;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        A a = new A(this.k, this.l, this.m, this.n, this.o, this.p, this.q, this.r, this.s, this.t, this.u, this.v, this.w, hVar);
        a.j = obj;
        return a;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((A) create((InterfaceC4289j0) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        androidx.glance.appwidget.protobuf.Z.e(obj);
        InterfaceC4289j0 interfaceC4289j0 = (InterfaceC4289j0) this.j;
        boolean z = interfaceC4289j0 instanceof com.quizlet.features.folders.data.X;
        if (z) {
            this.w.setValue(((com.quizlet.features.folders.data.X) interfaceC4289j0).a);
        }
        if (Intrinsics.b(interfaceC4289j0, C4275c0.a)) {
            com.quizlet.assembly.compose.modals.x.d(this.m);
        } else if (Intrinsics.b(interfaceC4289j0, com.quizlet.features.folders.data.Z.a)) {
            com.quizlet.assembly.compose.modals.x.d(this.n);
        } else if (Intrinsics.b(interfaceC4289j0, C4287i0.a)) {
            com.quizlet.assembly.compose.modals.x.d(this.l);
        } else if (Intrinsics.b(interfaceC4289j0, C4281f0.a)) {
            com.quizlet.assembly.compose.modals.x.d(this.r);
        } else if (Intrinsics.b(interfaceC4289j0, C4283g0.a)) {
            com.quizlet.assembly.compose.modals.x.d(this.q);
        } else if (Intrinsics.b(interfaceC4289j0, com.quizlet.features.folders.data.Y.a)) {
            com.quizlet.assembly.compose.modals.x.d(this.s);
        } else if (interfaceC4289j0 instanceof C4285h0) {
            this.k.c(((C4285h0) interfaceC4289j0).a);
        } else if (Intrinsics.b(interfaceC4289j0, C4279e0.a)) {
            com.quizlet.assembly.compose.modals.x.d(this.t);
        } else if (z) {
            com.quizlet.assembly.compose.modals.x.d(this.u);
        } else if (interfaceC4289j0 instanceof C4273b0) {
            C4273b0 c4273b0 = (C4273b0) interfaceC4289j0;
            Bundle bundleA = AbstractC3206m6.a(new Pair("NewTagModalArgs.ARG_PARENT_FOLDER_ID", Long.valueOf(c4273b0.a)), new Pair("NewTagModalArgs.ARG_CURRENT_FOLDER_TAGS", c4273b0.b.toArray(new String[0])));
            com.quizlet.assembly.compose.modals.x xVar = this.o;
            xVar.c = bundleA;
            ((L0) xVar.a).setValue(com.quizlet.assembly.compose.modals.y.a);
        } else if (interfaceC4289j0 instanceof C4271a0) {
            C4271a0 c4271a0 = (C4271a0) interfaceC4289j0;
            Bundle bundleA2 = AbstractC3206m6.a(new Pair("study_material_id", c4271a0.a), new Pair("study_material_type", c4271a0.b));
            com.quizlet.assembly.compose.modals.x xVar2 = this.v;
            xVar2.c = bundleA2;
            ((L0) xVar2.a).setValue(com.quizlet.assembly.compose.modals.y.a);
        } else {
            if (!(interfaceC4289j0 instanceof C4277d0)) {
                throw new NoWhenBranchMatchedException();
            }
            C4277d0 c4277d0 = (C4277d0) interfaceC4289j0;
            Bundle bundleA3 = AbstractC3206m6.a(new Pair("edit_tag_id", Long.valueOf(c4277d0.a)), new Pair("edit_tag_label", c4277d0.b));
            com.quizlet.assembly.compose.modals.x xVar3 = this.p;
            xVar3.c = bundleA3;
            ((L0) xVar3.a).setValue(com.quizlet.assembly.compose.modals.y.a);
        }
        return Unit.a;
    }
}

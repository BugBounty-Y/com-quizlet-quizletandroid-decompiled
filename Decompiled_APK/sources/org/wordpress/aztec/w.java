package org.wordpress.aztec;

import android.text.Editable;
import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.O;

/* loaded from: classes3.dex */
public final class w extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ AztecText k;
    public final /* synthetic */ Editable l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public w(AztecText aztecText, Editable editable, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = aztecText;
        this.l = editable;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new w(this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((w) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) throws Throwable {
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
        kotlinx.coroutines.scheduling.e eVar = O.a;
        kotlinx.coroutines.android.d dVar = kotlinx.coroutines.internal.m.a;
        v vVar = new v(this.k, this.l, null);
        this.j = 1;
        Object objJ = kotlinx.coroutines.E.J(dVar, vVar, this);
        return objJ == aVar ? aVar : objJ;
    }
}

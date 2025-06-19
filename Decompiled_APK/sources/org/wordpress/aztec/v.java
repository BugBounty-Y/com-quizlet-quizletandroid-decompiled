package org.wordpress.aztec;

import android.text.Editable;
import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final class v extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public final /* synthetic */ AztecText j;
    public final /* synthetic */ Editable k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public v(AztecText aztecText, Editable editable, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.j = aztecText;
        this.k = editable;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new v(this.j, this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((v) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        EnumC5145a enumC5145a = AztecText.q1;
        return this.j.m(this.k);
    }
}

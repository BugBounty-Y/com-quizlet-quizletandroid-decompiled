package com.quizlet.quizletandroid.ui.common.ads;

import android.view.View;
import android.view.ViewGroup;
import androidx.glance.appwidget.protobuf.Z;
import java.util.ArrayList;
import java.util.Iterator;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final class C extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public final /* synthetic */ boolean j;
    public final /* synthetic */ ViewGroup k;
    public final /* synthetic */ ArrayList l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C(boolean z, ViewGroup viewGroup, ArrayList arrayList, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.j = z;
        this.k = viewGroup;
        this.l = arrayList;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new C(this.j, this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C) create((Throwable) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        if (this.j) {
            this.k.setVisibility(8);
            Iterator it2 = this.l.iterator();
            while (it2.hasNext()) {
                ((View) it2.next()).setVisibility(8);
            }
        }
        return Unit.a;
    }
}

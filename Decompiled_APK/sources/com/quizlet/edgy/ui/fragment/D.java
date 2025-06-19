package com.quizlet.edgy.ui.fragment;

import android.content.Context;
import android.widget.ArrayAdapter;
import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.edgy.model.State;
import com.quizlet.quizletandroid.R;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes2.dex */
public final class D extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public /* synthetic */ Object j;
    public final /* synthetic */ EdgyAddSchoolManuallyFragment k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public D(EdgyAddSchoolManuallyFragment edgyAddSchoolManuallyFragment, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = edgyAddSchoolManuallyFragment;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        D d = new D(this.k, hVar);
        d.j = obj;
        return d;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((D) create((List) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        List list = (List) this.j;
        EdgyAddSchoolManuallyFragment edgyAddSchoolManuallyFragment = this.k;
        if (edgyAddSchoolManuallyFragment.n != null || list.isEmpty()) {
            return Unit.a;
        }
        Context contextRequireContext = edgyAddSchoolManuallyFragment.requireContext();
        ArrayList arrayList = new ArrayList(kotlin.collections.C.q(list, 10));
        Iterator it2 = list.iterator();
        while (it2.hasNext()) {
            arrayList.add(((State) it2.next()).b);
        }
        edgyAddSchoolManuallyFragment.n = new ArrayAdapter(contextRequireContext, R.layout.item_dropdown, arrayList);
        com.quizlet.edgy.databinding.c cVar = (com.quizlet.edgy.databinding.c) edgyAddSchoolManuallyFragment.J();
        cVar.f.setAdapter(edgyAddSchoolManuallyFragment.n);
        return Unit.a;
    }
}

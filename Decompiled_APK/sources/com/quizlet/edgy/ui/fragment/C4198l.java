package com.quizlet.edgy.ui.fragment;

import androidx.glance.appwidget.protobuf.Z;
import androidx.recyclerview.widget.C1364f;
import androidx.recyclerview.widget.RecyclerView;
import com.quizlet.edgy.ui.viewmodel.C4205f;
import com.quizlet.edgy.ui.viewmodel.C4206g;
import com.quizlet.edgy.ui.viewmodel.C4207h;
import com.quizlet.edgy.ui.viewmodel.C4208i;
import com.quizlet.edgy.ui.viewmodel.C4209j;
import com.quizlet.edgy.ui.viewmodel.C4210k;
import com.quizlet.edgy.ui.viewmodel.C4211l;
import java.util.ArrayList;
import java.util.List;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: com.quizlet.edgy.ui.fragment.l, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C4198l extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public /* synthetic */ Object j;
    public final /* synthetic */ EdgyAddSchoolAndCoursesFragment k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C4198l(EdgyAddSchoolAndCoursesFragment edgyAddSchoolAndCoursesFragment, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = edgyAddSchoolAndCoursesFragment;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        C4198l c4198l = new C4198l(this.k, hVar);
        c4198l.j = obj;
        return c4198l;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C4198l) create((com.quizlet.edgy.ui.viewmodel.s) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        final int i = 1;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        com.quizlet.edgy.ui.viewmodel.s sVar = (com.quizlet.edgy.ui.viewmodel.s) this.j;
        boolean z = sVar instanceof C4211l;
        final EdgyAddSchoolAndCoursesFragment edgyAddSchoolAndCoursesFragment = this.k;
        if (z) {
            ((C4211l) sVar).getClass();
            EdgyAddSchoolAndCoursesFragment.T(edgyAddSchoolAndCoursesFragment, C4211l.b);
        } else if (sVar instanceof C4209j) {
            ((C4209j) sVar).getClass();
            EdgyAddSchoolAndCoursesFragment.T(edgyAddSchoolAndCoursesFragment, C4209j.b);
        } else if (sVar instanceof C4208i) {
            ((C4208i) sVar).getClass();
            EdgyAddSchoolAndCoursesFragment.T(edgyAddSchoolAndCoursesFragment, C4208i.b);
        } else if (sVar instanceof com.quizlet.edgy.ui.viewmodel.n) {
            ((com.quizlet.edgy.ui.viewmodel.n) sVar).getClass();
            EdgyAddSchoolAndCoursesFragment.T(edgyAddSchoolAndCoursesFragment, com.quizlet.edgy.ui.viewmodel.n.b);
        } else if (sVar instanceof C4205f) {
            ((C4205f) sVar).getClass();
            EdgyAddSchoolAndCoursesFragment.T(edgyAddSchoolAndCoursesFragment, C4205f.b);
        } else if (sVar instanceof C4210k) {
            ((C4210k) sVar).getClass();
            EdgyAddSchoolAndCoursesFragment.T(edgyAddSchoolAndCoursesFragment, C4210k.b);
        } else {
            boolean z2 = sVar instanceof com.quizlet.edgy.ui.viewmodel.q;
            kotlin.u uVar = edgyAddSchoolAndCoursesFragment.l;
            if (z2) {
                com.quizlet.edgy.ui.viewmodel.q qVar = (com.quizlet.edgy.ui.viewmodel.q) sVar;
                EdgyAddSchoolAndCoursesFragment.T(edgyAddSchoolAndCoursesFragment, qVar.b);
                final List list = qVar.a;
                if (list == null) {
                    list = kotlin.collections.K.a;
                }
                com.quizlet.edgy.ui.recyclerview.adapter.h hVar = (com.quizlet.edgy.ui.recyclerview.adapter.h) uVar.getValue();
                ((C1364f) hVar.b).b(list, new Runnable() { // from class: com.quizlet.edgy.ui.fragment.i
                    @Override // java.lang.Runnable
                    public final void run() {
                        com.quizlet.edgy.databinding.b bVar;
                        RecyclerView recyclerView;
                        com.quizlet.edgy.databinding.b bVar2;
                        RecyclerView recyclerView2;
                        EdgyAddSchoolAndCoursesFragment edgyAddSchoolAndCoursesFragment2 = edgyAddSchoolAndCoursesFragment;
                        List list2 = list;
                        switch (i) {
                            case 0:
                                String str = EdgyAddSchoolAndCoursesFragment.u;
                                if (!list2.isEmpty() && (bVar = (com.quizlet.edgy.databinding.b) edgyAddSchoolAndCoursesFragment2.d) != null && (recyclerView = bVar.e) != null) {
                                    recyclerView.k0(0);
                                    break;
                                }
                                break;
                            default:
                                String str2 = EdgyAddSchoolAndCoursesFragment.u;
                                if (!list2.isEmpty() && (bVar2 = (com.quizlet.edgy.databinding.b) edgyAddSchoolAndCoursesFragment2.d) != null && (recyclerView2 = bVar2.e) != null) {
                                    recyclerView2.k0(0);
                                    break;
                                }
                                break;
                        }
                    }
                });
            } else if (sVar instanceof com.quizlet.edgy.ui.viewmodel.p) {
                com.quizlet.edgy.ui.viewmodel.p pVar = (com.quizlet.edgy.ui.viewmodel.p) sVar;
                EdgyAddSchoolAndCoursesFragment.T(edgyAddSchoolAndCoursesFragment, pVar.b);
                final ArrayList arrayList = pVar.a;
                com.quizlet.edgy.ui.recyclerview.adapter.h hVar2 = (com.quizlet.edgy.ui.recyclerview.adapter.h) uVar.getValue();
                ((C1364f) hVar2.b).b(arrayList, new Runnable() { // from class: com.quizlet.edgy.ui.fragment.i
                    @Override // java.lang.Runnable
                    public final void run() {
                        com.quizlet.edgy.databinding.b bVar;
                        RecyclerView recyclerView;
                        com.quizlet.edgy.databinding.b bVar2;
                        RecyclerView recyclerView2;
                        EdgyAddSchoolAndCoursesFragment edgyAddSchoolAndCoursesFragment2 = edgyAddSchoolAndCoursesFragment;
                        List list2 = arrayList;
                        switch (i) {
                            case 0:
                                String str = EdgyAddSchoolAndCoursesFragment.u;
                                if (!list2.isEmpty() && (bVar = (com.quizlet.edgy.databinding.b) edgyAddSchoolAndCoursesFragment2.d) != null && (recyclerView = bVar.e) != null) {
                                    recyclerView.k0(0);
                                    break;
                                }
                                break;
                            default:
                                String str2 = EdgyAddSchoolAndCoursesFragment.u;
                                if (!list2.isEmpty() && (bVar2 = (com.quizlet.edgy.databinding.b) edgyAddSchoolAndCoursesFragment2.d) != null && (recyclerView2 = bVar2.e) != null) {
                                    recyclerView2.k0(0);
                                    break;
                                }
                                break;
                        }
                    }
                });
            } else if (sVar instanceof C4207h) {
                C4207h c4207h = (C4207h) sVar;
                EdgyAddSchoolAndCoursesFragment.T(edgyAddSchoolAndCoursesFragment, c4207h.c);
                com.quizlet.edgy.databinding.b bVar = (com.quizlet.edgy.databinding.b) edgyAddSchoolAndCoursesFragment.J();
                bVar.h.setText(c4207h.a.b);
                com.quizlet.edgy.ui.recyclerview.adapter.f fVar = (com.quizlet.edgy.ui.recyclerview.adapter.f) edgyAddSchoolAndCoursesFragment.m.getValue();
                final List list2 = c4207h.b;
                final int i2 = 0;
                ((C1364f) fVar.b).b(list2, new Runnable() { // from class: com.quizlet.edgy.ui.fragment.i
                    @Override // java.lang.Runnable
                    public final void run() {
                        com.quizlet.edgy.databinding.b bVar2;
                        RecyclerView recyclerView;
                        com.quizlet.edgy.databinding.b bVar22;
                        RecyclerView recyclerView2;
                        EdgyAddSchoolAndCoursesFragment edgyAddSchoolAndCoursesFragment2 = edgyAddSchoolAndCoursesFragment;
                        List list22 = list2;
                        switch (i2) {
                            case 0:
                                String str = EdgyAddSchoolAndCoursesFragment.u;
                                if (!list22.isEmpty() && (bVar2 = (com.quizlet.edgy.databinding.b) edgyAddSchoolAndCoursesFragment2.d) != null && (recyclerView = bVar2.e) != null) {
                                    recyclerView.k0(0);
                                    break;
                                }
                                break;
                            default:
                                String str2 = EdgyAddSchoolAndCoursesFragment.u;
                                if (!list22.isEmpty() && (bVar22 = (com.quizlet.edgy.databinding.b) edgyAddSchoolAndCoursesFragment2.d) != null && (recyclerView2 = bVar22.e) != null) {
                                    recyclerView2.k0(0);
                                    break;
                                }
                                break;
                        }
                    }
                });
            } else if (sVar instanceof com.quizlet.edgy.ui.viewmodel.o) {
                String str = EdgyAddSchoolAndCoursesFragment.u;
                com.quizlet.edgy.databinding.b bVar2 = (com.quizlet.edgy.databinding.b) edgyAddSchoolAndCoursesFragment.J();
                com.quizlet.edgy.ui.viewmodel.o oVar = (com.quizlet.edgy.ui.viewmodel.o) sVar;
                bVar2.h.setText(oVar.a.b);
                EdgyAddSchoolAndCoursesFragment.T(edgyAddSchoolAndCoursesFragment, oVar.b);
            } else {
                if (!(sVar instanceof C4206g)) {
                    throw new NoWhenBranchMatchedException();
                }
                String str2 = EdgyAddSchoolAndCoursesFragment.u;
                com.quizlet.edgy.databinding.b bVar3 = (com.quizlet.edgy.databinding.b) edgyAddSchoolAndCoursesFragment.J();
                C4206g c4206g = (C4206g) sVar;
                bVar3.h.setText(c4206g.a.b);
                ArrayList arrayList2 = c4206g.b;
                com.quizlet.edgy.ui.recyclerview.adapter.c cVar = (com.quizlet.edgy.ui.recyclerview.adapter.c) edgyAddSchoolAndCoursesFragment.n.getValue();
                ((C1364f) cVar.b).b(arrayList2, new com.google.firebase.crashlytics.internal.common.i(18, arrayList2, edgyAddSchoolAndCoursesFragment));
                EdgyAddSchoolAndCoursesFragment.T(edgyAddSchoolAndCoursesFragment, c4206g.c);
            }
        }
        return Unit.a;
    }
}

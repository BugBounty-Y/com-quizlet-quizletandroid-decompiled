package androidx.recyclerview.widget;

import com.quizlet.db.data.models.persisted.DBTerm;
import com.quizlet.diagrams.layoutmanager.DiagramCardLayoutManager;
import com.quizlet.quizletandroid.ui.diagramming.DiagramOverviewActivity;
import com.quizlet.quizletandroid.ui.diagramming.DiagramOverviewFragment;
import com.quizlet.quizletandroid.ui.setcreation.fragments.EditSetFragment;
import kotlin.Pair;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.recyclerview.widget.z, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1397z extends AbstractC1390s0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;

    public /* synthetic */ C1397z(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    @Override // androidx.recyclerview.widget.AbstractC1390s0
    public void a(RecyclerView recyclerView, int i) {
        switch (this.a) {
            case 2:
                Intrinsics.checkNotNullParameter(recyclerView, "recyclerView");
                EditSetFragment editSetFragment = (EditSetFragment) this.b;
                if (i == 0) {
                    androidx.appcompat.app.K k = editSetFragment.E;
                    if (k != null) {
                        if (k.a) {
                            ((io.reactivex.rxjava3.subjects.d) k.b).b(Boolean.FALSE);
                        }
                        k.a = false;
                    }
                    androidx.core.util.c cVar = editSetFragment.B;
                    if (cVar != null) {
                        com.quizlet.quizletandroid.ui.setcreation.fragments.f fVar = (com.quizlet.quizletandroid.ui.setcreation.fragments.f) cVar.b;
                        if (fVar != null) {
                            EditSetFragment editSetFragment2 = fVar.a;
                            androidx.appcompat.app.K k2 = editSetFragment2.E;
                            if (k2 != null) {
                                if (k2.a) {
                                    ((io.reactivex.rxjava3.subjects.d) k2.b).b(Boolean.FALSE);
                                }
                                k2.a = false;
                            }
                            com.quizlet.quizletandroid.ui.setcreation.adapters.f fVar2 = editSetFragment2.A;
                            if (fVar2 != null) {
                                int i2 = com.quizlet.quizletandroid.ui.setcreation.adapters.e.a[fVar.c.ordinal()];
                                int i3 = fVar.b;
                                if (i2 == 1) {
                                    fVar2.notifyItemChanged(i3, Integer.valueOf(com.pubmatic.sdk.video.a.GENERAL_COMPANION_AD_ERROR));
                                } else if (i2 == 2) {
                                    fVar2.notifyItemChanged(i3, 700);
                                }
                            }
                        }
                        editSetFragment.B = null;
                        break;
                    }
                } else if (i == 1) {
                    androidx.appcompat.app.K k3 = editSetFragment.E;
                    if (k3 != null) {
                        if (!k3.a) {
                            ((io.reactivex.rxjava3.subjects.d) k3.b).b(Boolean.TRUE);
                        }
                        k3.a = true;
                    }
                    editSetFragment.B = null;
                    break;
                }
                break;
        }
    }

    @Override // androidx.recyclerview.widget.AbstractC1390s0
    public final void b(RecyclerView recyclerView, int i, int i2) {
        com.quizlet.quizletandroid.ui.setcreation.adapters.f fVar;
        switch (this.a) {
            case 0:
                int iComputeHorizontalScrollOffset = recyclerView.computeHorizontalScrollOffset();
                int iComputeVerticalScrollOffset = recyclerView.computeVerticalScrollOffset();
                B b = (B) this.b;
                int iComputeVerticalScrollRange = b.s.computeVerticalScrollRange();
                int i3 = b.r;
                int i4 = iComputeVerticalScrollRange - i3;
                int i5 = b.a;
                b.t = i4 > 0 && i3 >= i5;
                int iComputeHorizontalScrollRange = b.s.computeHorizontalScrollRange();
                int i6 = b.q;
                boolean z = iComputeHorizontalScrollRange - i6 > 0 && i6 >= i5;
                b.u = z;
                boolean z2 = b.t;
                if (!z2 && !z) {
                    if (b.v != 0) {
                        b.i(0);
                        return;
                    }
                    return;
                }
                if (z2) {
                    float f = i3;
                    b.l = (int) ((((f / 2.0f) + iComputeVerticalScrollOffset) * f) / iComputeVerticalScrollRange);
                    b.k = Math.min(i3, (i3 * i3) / iComputeVerticalScrollRange);
                }
                if (b.u) {
                    float f2 = iComputeHorizontalScrollOffset;
                    float f3 = i6;
                    b.o = (int) ((((f3 / 2.0f) + f2) * f3) / iComputeHorizontalScrollRange);
                    b.n = Math.min(i6, (i6 * i6) / iComputeHorizontalScrollRange);
                }
                int i7 = b.v;
                if (i7 == 0 || i7 == 1) {
                    b.i(1);
                    return;
                }
                return;
            case 1:
                Intrinsics.checkNotNullParameter(recyclerView, "recyclerView");
                DiagramOverviewFragment diagramOverviewFragment = (DiagramOverviewFragment) this.b;
                int iQ1 = ((DiagramCardLayoutManager) diagramOverviewFragment.n.getValue()).q1();
                Integer numValueOf = Integer.valueOf(iQ1);
                if (iQ1 < 0) {
                    numValueOf = null;
                }
                if (numValueOf != null) {
                    int iIntValue = numValueOf.intValue();
                    com.quizlet.diagrams.e eVar = diagramOverviewFragment.m;
                    if (eVar == null) {
                        Intrinsics.m("adapter");
                        throw null;
                    }
                    Pair termData = (Pair) eVar.a.get(iIntValue);
                    diagramOverviewFragment.V(((DBTerm) termData.a).getId());
                    com.quizlet.diagrams.e eVar2 = diagramOverviewFragment.m;
                    if (eVar2 == null) {
                        Intrinsics.m("adapter");
                        throw null;
                    }
                    long id = ((DBTerm) termData.a).getId();
                    if (eVar2.c != id) {
                        eVar2.c = id;
                        eVar2.notifyDataSetChanged();
                    }
                    com.quizlet.quizletandroid.ui.diagramming.h hVar = diagramOverviewFragment.l;
                    if (hVar != null) {
                        Intrinsics.checkNotNullParameter(termData, "termData");
                        ((DiagramOverviewActivity) hVar).b0(termData);
                        return;
                    }
                    return;
                }
                return;
            default:
                Intrinsics.checkNotNullParameter(recyclerView, "recyclerView");
                if ((i == 0 && i2 == 0) || (fVar = ((EditSetFragment) this.b).A) == null) {
                    return;
                }
                fVar.m();
                return;
        }
    }
}

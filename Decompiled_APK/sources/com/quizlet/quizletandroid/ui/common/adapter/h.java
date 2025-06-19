package com.quizlet.quizletandroid.ui.common.adapter;

import android.content.Context;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import androidx.recyclerview.widget.AbstractC1361d0;
import androidx.recyclerview.widget.F0;
import com.google.android.gms.internal.mlkit_vision_barcode.K6;
import com.quizlet.db.data.models.base.SortOption;
import com.quizlet.db.data.models.persisted.DBSelectedTerm;
import com.quizlet.db.data.models.persisted.DBTerm;
import com.quizlet.eventlogger.EventLogger;
import com.quizlet.explanations.databinding.n;
import com.quizlet.generated.enums.O1;
import com.quizlet.partskit.widgets.QTextView;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.databinding.C4612p;
import com.quizlet.quizletandroid.databinding.M;
import com.quizlet.quizletandroid.u;
import com.quizlet.quizletandroid.ui.common.adapter.viewholder.i;
import com.quizlet.quizletandroid.ui.common.adapter.viewholder.k;
import com.quizlet.quizletandroid.ui.common.adapter.viewholder.l;
import com.quizlet.quizletandroid.ui.diagramming.DiagramView;
import com.quizlet.studiablemodels.diagrams.DiagramData;
import java.io.IOException;
import java.util.ArrayList;
import kotlin.Pair;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class h extends AbstractC1361d0 implements k, com.quizlet.quizletandroid.ui.common.adapter.presenter.d {
    public final Context a;
    public final com.quizlet.quizletandroid.ui.common.adapter.presenter.e b;
    public final EventLogger e;
    public final com.quizlet.quizletandroid.managers.audio.h f;
    public final com.quizlet.infra.legacysyncengine.managers.d g;
    public final com.quizlet.infra.legacysyncengine.net.f h;
    public final com.quizlet.db.a i;
    public final ArrayList c = new ArrayList();
    public final ArrayList d = new ArrayList();
    public final io.reactivex.rxjava3.disposables.d j = new io.reactivex.rxjava3.disposables.d(io.reactivex.rxjava3.internal.functions.d.b, 0);
    public f k = new com.quizlet.infra.legacysyncengine.models.serializers.a(15);
    public g l = new com.quizlet.infra.legacysyncengine.models.serializers.a(16);
    public d m = new c();

    public h(Context context, com.quizlet.quizletandroid.ui.setpage.terms.b bVar) {
        u uVar = (u) ((com.quizlet.quizletandroid.injection.components.a) K6.b(com.quizlet.quizletandroid.injection.components.a.class, context.getApplicationContext()));
        this.e = (EventLogger) uVar.l0.get();
        this.f = (com.quizlet.quizletandroid.managers.audio.h) uVar.f0.get();
        this.g = (com.quizlet.infra.legacysyncengine.managers.d) uVar.Z.get();
        this.h = (com.quizlet.infra.legacysyncengine.net.f) uVar.U.get();
        this.i = uVar.Z();
        io.ktor.client.plugins.api.d dVarG = uVar.g();
        this.a = context;
        this.b = new com.quizlet.quizletandroid.ui.common.adapter.presenter.e(this.g, this.h, this.f, bVar, dVarG);
        setHasStableIds(true);
    }

    @Override // com.quizlet.quizletandroid.ui.common.adapter.viewholder.k
    public final void a(DBTerm dBTerm, O1 o1, boolean z) {
        this.b.c(this.a, this, dBTerm, o1, z);
        this.m.a();
    }

    @Override // com.quizlet.quizletandroid.ui.common.adapter.viewholder.k
    public final void b(DBTerm dBTerm) {
        this.b.d.e(dBTerm.getDefinitionImageLargeUrl());
    }

    @Override // com.quizlet.quizletandroid.ui.common.adapter.viewholder.k
    public final void c(DBTerm dBTerm, DBSelectedTerm dBSelectedTerm) {
        this.b.b(dBTerm, dBSelectedTerm, 6);
        this.m.b();
    }

    public final Pair d(int i) {
        ArrayList arrayList = this.d;
        int size = (i - 1) - arrayList.size();
        if (arrayList.size() > 0) {
            size--;
        }
        return (Pair) this.c.get(size);
    }

    @Override // com.quizlet.quizletandroid.ui.common.adapter.presenter.d
    public final void e(DBTerm dBTerm) {
        int size;
        ArrayList arrayList = this.c;
        if (arrayList == null || arrayList.size() == 0) {
            size = -1;
        } else {
            ArrayList arrayList2 = this.d;
            int i = (arrayList2.size() > 0 ? 1 : 0) + 1;
            for (int i2 = 0; i2 < arrayList.size(); i2++) {
                if (((DBTerm) ((Pair) arrayList.get(i2)).a).getId() == dBTerm.getId()) {
                    size = arrayList2.size() + i2 + i;
                    break;
                }
            }
            size = -1;
        }
        if (size == -1) {
            notifyDataSetChanged();
        } else {
            notifyItemChanged(size);
        }
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final int getItemCount() {
        ArrayList arrayList = this.d;
        int size = this.c.size() + arrayList.size();
        return arrayList.size() > 0 ? size + 2 : size + 1;
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final long getItemId(int i) {
        int itemViewType = getItemViewType(i);
        ArrayList arrayList = this.d;
        if (itemViewType == R.layout.diagram_listitem) {
            return ((DiagramData) arrayList.get(i - 1)).getSetId();
        }
        if (itemViewType == R.layout.set_term_item_view) {
            return ((DBTerm) d(i).a).getLocalId();
        }
        if (itemViewType == R.layout.listitem_setpage_section_header) {
            return (i != 0 || arrayList.size() <= 0) ? 2L : 1L;
        }
        return -1L;
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final int getItemViewType(int i) {
        if (i == 0) {
            return R.layout.listitem_setpage_section_header;
        }
        ArrayList arrayList = this.d;
        return (arrayList.size() <= 0 || i != arrayList.size() + 1) ? i <= arrayList.size() ? R.layout.diagram_listitem : R.layout.set_term_item_view : R.layout.listitem_setpage_section_header;
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final void onBindViewHolder(F0 f0, int i) throws IOException {
        String string;
        boolean z = f0 instanceof com.quizlet.quizletandroid.ui.common.adapter.viewholder.g;
        ArrayList arrayList = this.d;
        if (z) {
            DiagramData diagramData = (DiagramData) arrayList.get(i - 1);
            com.quizlet.quizletandroid.ui.common.adapter.viewholder.g gVar = (com.quizlet.quizletandroid.ui.common.adapter.viewholder.g) f0;
            f listener = this.k;
            gVar.getClass();
            Intrinsics.checkNotNullParameter(diagramData, "diagramData");
            Intrinsics.checkNotNullParameter(listener, "listener");
            DiagramView diagramView = ((C4612p) gVar.e()).b;
            diagramView.d(diagramData, com.quizlet.diagrams.b.c);
            diagramView.f();
            io.reactivex.rxjava3.internal.observers.h hVar = gVar.d;
            if (hVar == null || hVar.c()) {
                gVar.d = (io.reactivex.rxjava3.internal.observers.h) diagramView.getClicks().u(new com.quizlet.billing.manager.b(10, listener, diagramData), io.reactivex.rxjava3.internal.functions.d.e, io.reactivex.rxjava3.internal.functions.d.c);
                return;
            }
            return;
        }
        if (f0 instanceof l) {
            Pair pairD = d(i);
            ((l) f0).c((DBTerm) pairD.a, (DBSelectedTerm) pairD.b, this.b.a((DBTerm) pairD.a));
            return;
        }
        if (!(f0 instanceof i)) {
            throw new IllegalArgumentException("bad ViewHolder: " + f0.toString());
        }
        if (i == 0 && arrayList.size() > 0) {
            i iVar = (i) f0;
            ((M) iVar.e()).b.setText(R.string.set_page_list_header_diagram);
            ((M) iVar.e()).c.setVisibility(8);
            return;
        }
        ArrayList arrayList2 = this.c;
        Long lValueOf = arrayList2.isEmpty() ? null : Long.valueOf(((DBTerm) ((Pair) arrayList2.get(0)).a).getSetId());
        i iVar2 = (i) f0;
        g listener2 = this.l;
        com.quizlet.db.a globalSharedPreferencesManager = this.i;
        iVar2.getClass();
        Intrinsics.checkNotNullParameter(listener2, "listener");
        Intrinsics.checkNotNullParameter(globalSharedPreferencesManager, "globalSharedPreferencesManager");
        ((M) iVar2.e()).b.setText(R.string.set_page_list_header_cards);
        if (lValueOf == null) {
            return;
        }
        SortOption sortOptionA = globalSharedPreferencesManager.a(lValueOf.longValue());
        Intrinsics.checkNotNullExpressionValue(sortOptionA, "getSetPageSortOption(...)");
        ((M) iVar2.e()).c.setOnClickListener(new com.quizlet.quizletandroid.ui.common.adapter.viewholder.h(listener2, 0));
        QTextView qTextView = ((M) iVar2.e()).d;
        SortOption sortOption = SortOption.ORIGINAL;
        Context context = iVar2.b;
        if (sortOptionA == sortOption) {
            string = context.getString(R.string.original_sort);
        } else {
            if (sortOptionA != SortOption.ALPHABETICAL_BY_WORD) {
                throw new IllegalArgumentException("Invalid sort option");
            }
            string = context.getString(R.string.alphabetical_sort);
        }
        qTextView.setText(string);
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final F0 onCreateViewHolder(ViewGroup viewGroup, int i) {
        LayoutInflater layoutInflaterFrom = LayoutInflater.from(viewGroup.getContext());
        if (i == R.layout.listitem_setpage_section_header) {
            View itemView = layoutInflaterFrom.inflate(R.layout.listitem_setpage_section_header, viewGroup, false);
            Intrinsics.checkNotNullParameter(itemView, "itemView");
            return new i(itemView);
        }
        if (i == R.layout.diagram_listitem) {
            View itemView2 = layoutInflaterFrom.inflate(R.layout.diagram_listitem, viewGroup, false);
            Intrinsics.checkNotNullParameter(itemView2, "itemView");
            return new com.quizlet.quizletandroid.ui.common.adapter.viewholder.g(itemView2);
        }
        if (i == R.layout.set_term_item_view) {
            return new l(n.a(layoutInflaterFrom, viewGroup), this);
        }
        throw new IllegalArgumentException(android.support.v4.media.session.a.f(i, "bad viewType: "));
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final void onViewRecycled(F0 f0) {
        super.onViewRecycled(f0);
        if (f0 instanceof com.quizlet.quizletandroid.ui.common.adapter.viewholder.g) {
            com.quizlet.quizletandroid.ui.common.adapter.viewholder.g gVar = (com.quizlet.quizletandroid.ui.common.adapter.viewholder.g) f0;
            io.reactivex.rxjava3.internal.observers.h hVar = gVar.d;
            if (hVar != null && !hVar.c()) {
                io.reactivex.rxjava3.internal.disposables.a.a(hVar);
            }
            gVar.d = null;
        }
    }
}

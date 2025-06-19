package com.quizlet.quizletandroid.ui.common.adapter;

import android.content.Context;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ArrayAdapter;
import androidx.cardview.widget.CardView;
import androidx.collection.C0219q;
import com.google.android.gms.internal.mlkit_vision_barcode.K6;
import com.quizlet.db.data.caches.UserInfoCache;
import com.quizlet.db.data.models.persisted.DBSelectedTerm;
import com.quizlet.db.data.models.persisted.DBTerm;
import com.quizlet.db.data.models.persisted.base.Models;
import com.quizlet.explanations.databinding.n;
import com.quizlet.generated.enums.O1;
import com.quizlet.infra.legacysyncengine.managers.i;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.u;
import com.quizlet.quizletandroid.ui.common.adapter.viewholder.k;
import com.quizlet.quizletandroid.ui.common.adapter.viewholder.l;
import java.util.Collection;
import java.util.Iterator;

/* loaded from: classes3.dex */
public final class b extends ArrayAdapter implements k, com.quizlet.quizletandroid.ui.common.adapter.presenter.d {
    public final Context a;
    public final com.quizlet.quizletandroid.ui.common.adapter.presenter.e b;
    public final int c;
    public C0219q d;
    public final com.quizlet.infra.legacysyncengine.net.f e;
    public final i f;
    public final UserInfoCache g;

    public b(Context context, com.quizlet.quizletandroid.ui.common.adapter.presenter.e eVar) {
        super(context, R.layout.set_termlist_item);
        u uVar = (u) ((com.quizlet.quizletandroid.injection.components.a) K6.b(com.quizlet.quizletandroid.injection.components.a.class, context.getApplicationContext()));
        this.e = (com.quizlet.infra.legacysyncengine.net.f) uVar.U.get();
        this.f = (i) uVar.S.get();
        uVar.Z();
        this.g = uVar.l0();
        this.a = context;
        this.b = eVar;
        this.c = 5;
    }

    @Override // com.quizlet.quizletandroid.ui.common.adapter.viewholder.k
    public final void a(DBTerm dBTerm, O1 o1, boolean z) {
        this.b.c(this.a, this, dBTerm, o1, z);
    }

    @Override // android.widget.ArrayAdapter
    public final void addAll(Collection collection) {
        Iterator it2 = collection.iterator();
        while (it2.hasNext()) {
            add((DBTerm) it2.next());
        }
    }

    @Override // android.widget.BaseAdapter, android.widget.ListAdapter
    public final boolean areAllItemsEnabled() {
        return false;
    }

    @Override // com.quizlet.quizletandroid.ui.common.adapter.viewholder.k
    public final void b(DBTerm dBTerm) {
        this.b.d.e(dBTerm.getDefinitionImageLargeUrl());
    }

    @Override // com.quizlet.quizletandroid.ui.common.adapter.viewholder.k
    public final void c(DBTerm dBTerm, DBSelectedTerm dBSelectedTerm) {
        this.b.b(dBTerm, dBSelectedTerm, this.c);
    }

    public final boolean d() {
        for (int i = 0; i < getCount(); i++) {
            DBSelectedTerm dBSelectedTermF = f((DBTerm) getItem(i));
            if (dBSelectedTermF == null || dBSelectedTermF.getDeleted()) {
                return false;
            }
        }
        return true;
    }

    @Override // com.quizlet.quizletandroid.ui.common.adapter.presenter.d
    public final void e(DBTerm dBTerm) {
        notifyDataSetChanged();
    }

    public final DBSelectedTerm f(DBTerm dBTerm) {
        if (dBTerm == null) {
            return null;
        }
        return (DBSelectedTerm) this.d.d(dBTerm.getId(), (DBSelectedTerm) this.d.d(dBTerm.getLocalId(), null));
    }

    public final void g(boolean z) {
        boolean z2;
        i iVar = this.f;
        boolean z3 = false;
        for (int i = 0; i < getCount(); i++) {
            DBTerm dBTerm = (DBTerm) getItem(i);
            DBSelectedTerm dBSelectedTermF = f(dBTerm);
            if (z) {
                if (dBSelectedTermF == null || dBSelectedTermF.getDeleted()) {
                    DBSelectedTerm dBSelectedTerm = new DBSelectedTerm(this.g.getPersonId(), dBTerm.getSetId(), dBTerm.getId(), System.currentTimeMillis() / 1000, this.c);
                    iVar.c(dBSelectedTerm);
                    this.d.g(dBSelectedTerm.getLocalId(), dBSelectedTerm);
                    z2 = true;
                }
                z2 = false;
            } else {
                if (dBSelectedTermF != null && !dBSelectedTermF.getDeleted()) {
                    dBSelectedTermF.setDeleted(true);
                    iVar.c(dBSelectedTermF);
                    this.d.h(dBSelectedTermF.getLocalId());
                    z2 = true;
                }
                z2 = false;
            }
            z3 |= z2;
        }
        if (z3) {
            this.e.c(Models.SELECTED_TERM);
        }
    }

    @Override // android.widget.ArrayAdapter, android.widget.Adapter
    public final View getView(int i, View view, ViewGroup viewGroup) {
        l lVar;
        if (view == null) {
            n nVarA = n.a(LayoutInflater.from(viewGroup.getContext()), viewGroup);
            lVar = new l(nVarA, this);
            view = (CardView) nVarA.c;
            view.setTag(lVar);
        } else {
            lVar = (l) view.getTag();
        }
        DBTerm dBTerm = (DBTerm) getItem(i);
        lVar.c(dBTerm, f(dBTerm), this.b.a(dBTerm));
        return view;
    }

    @Override // android.widget.BaseAdapter, android.widget.ListAdapter
    public final boolean isEnabled(int i) {
        return false;
    }
}

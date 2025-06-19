package com.quizlet.quizletandroid.ui.group.addclassset;

import android.content.Context;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;
import androidx.compose.foundation.text.input.internal.u;
import androidx.fragment.app.I;
import androidx.recyclerview.widget.AbstractC1361d0;
import androidx.work.impl.model.n;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3525r4;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3543u4;
import com.google.android.gms.measurement.internal.Z;
import com.quizlet.db.data.models.persisted.DBStudySet;
import com.quizlet.db.data.models.persisted.base.Models;
import com.quizlet.db.data.models.persisted.fields.DBGroupSetFields;
import com.quizlet.partskit.widgets.icon.IconFontTextView;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.ui.activitycenter.views.i;
import com.quizlet.quizletandroid.ui.base.ViewModelDataSourceRecyclerViewFragment;
import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.ListIterator;
import java.util.function.IntFunction;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public abstract class AddToClassSetListFragment extends ViewModelDataSourceRecyclerViewFragment<DBStudySet> {
    public WeakReference u;
    public com.quizlet.features.infra.legacyadapter.helper.a v;
    public n x;
    public com.quizlet.features.infra.legacyadapter.e z;
    public final ArrayList t = new ArrayList();
    public final i w = new i(this, 1);
    public boolean y = false;
    public final c A = new c(this);

    @Override // com.quizlet.baseui.base.BaseFragment
    public final String N() {
        return "AddToClassSetListFragment";
    }

    @Override // com.quizlet.features.infra.legacyadapter.RecyclerViewFragment
    public final AbstractC1361d0 Q() {
        com.quizlet.features.infra.legacyadapter.helper.a aVar = new com.quizlet.features.infra.legacyadapter.helper.a(this.A);
        this.v = aVar;
        com.quizlet.features.infra.legacyadapter.e eVar = new com.quizlet.features.infra.legacyadapter.e(aVar, this.w, null);
        this.z = eVar;
        return eVar;
    }

    @Override // com.quizlet.features.infra.legacyadapter.RecyclerViewFragment
    public final View R(ViewGroup viewGroup) {
        View viewC = Z.c(viewGroup, R.layout.view_empty_viewable_list, viewGroup, false);
        ((IconFontTextView) viewC.findViewById(R.id.empty_icon)).setIcon("flashcards");
        ((TextView) viewC.findViewById(R.id.empty_message)).setText(b0());
        return viewC;
    }

    @Override // com.quizlet.features.infra.legacyadapter.RecyclerViewFragment
    public final boolean T(int i) {
        return true;
    }

    @Override // com.quizlet.features.infra.legacyadapter.RecyclerViewFragment
    public final boolean V() {
        return false;
    }

    @Override // com.quizlet.quizletandroid.ui.base.ViewModelDataSourceRecyclerViewFragment
    public final void W(List list) {
        ArrayList arrayList = new ArrayList(list);
        ListIterator listIterator = arrayList.listIterator();
        while (listIterator.hasNext()) {
            if (this.x.g((DBStudySet) listIterator.next())) {
                listIterator.remove();
            }
        }
        this.z.g(arrayList);
        if (this.y || arrayList.size() <= 0) {
            return;
        }
        ArrayList arrayList2 = this.t;
        if (arrayList2.size() > 0) {
            this.y = true;
            for (DBStudySet dBStudySet : AbstractC3525r4.e(arrayList2, new com.quizlet.baserecyclerview.decoration.a(26))) {
                if (!this.v.a.contains(Long.valueOf(dBStudySet.getId()))) {
                    com.google.mlkit.vision.documentscanner.internal.c cVar = this.z.f;
                    if ((cVar == null ? -1 : cVar.e().indexOf(dBStudySet)) != -1) {
                        this.v.a.add(Long.valueOf(dBStudySet.getId()));
                    }
                }
            }
            this.A.a.z.notifyDataSetChanged();
        }
    }

    @Override // com.quizlet.quizletandroid.ui.base.ViewModelDataSourceRecyclerViewFragment
    public final boolean a0() {
        return false;
    }

    public abstract int b0();

    /* JADX WARN: Multi-variable type inference failed */
    @Override // com.quizlet.baseui.base.BaseFragment, com.quizlet.baseui.di.BaseDaggerFragment, androidx.fragment.app.Fragment
    public void onAttach(Context context) {
        super.onAttach(context);
        this.u = new WeakReference((d) context);
    }

    @Override // com.quizlet.quizletandroid.ui.base.ViewModelDataSourceRecyclerViewFragment, com.quizlet.features.infra.legacyadapter.RecyclerViewFragment, com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        AddClassSetActivity addClassSetActivity = (AddClassSetActivity) ((d) this.u.get());
        u uVar = addClassSetActivity.s;
        Long l = addClassSetActivity.v;
        l.getClass();
        if (((com.quizlet.infra.legacysyncengine.orm.query.a) uVar.c) == null) {
            com.quizlet.infra.legacysyncengine.orm.b bVar = new com.quizlet.infra.legacysyncengine.orm.b(Models.GROUP_SET);
            bVar.b(l, DBGroupSetFields.GROUP);
            bVar.e(DBGroupSetFields.SET);
            uVar.c = bVar.a();
        }
        com.quizlet.infra.legacysyncengine.orm.query.a aVar = (com.quizlet.infra.legacysyncengine.orm.query.a) uVar.c;
        if (aVar == null) {
            Intrinsics.m("groupSetQuery");
            throw null;
        }
        io.reactivex.rxjava3.internal.operators.single.g gVarG = ((com.quizlet.infra.legacysyncengine.net.c) uVar.b).b(aVar, com.quizlet.infra.legacysyncengine.net.b.a).g(com.quizlet.quizletandroid.ui.group.addclassset.data.a.a);
        Intrinsics.checkNotNullExpressionValue(gVarG, "map(...)");
        H(new io.reactivex.rxjava3.internal.operators.single.d(gVarG, new com.quizlet.billing.subscriptions.a(addClassSetActivity, 12), 2).i(new com.quizlet.billing.subscriptions.a(this, 13), io.reactivex.rxjava3.internal.functions.d.e));
    }

    @Override // com.quizlet.features.infra.legacyadapter.RecyclerViewFragment, com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final View onCreateView(LayoutInflater layoutInflater, ViewGroup viewGroup, Bundle bundle) {
        Long[] lArr;
        View viewOnCreateView = super.onCreateView(layoutInflater, viewGroup, bundle);
        com.quizlet.features.infra.legacyadapter.helper.a aVar = this.v;
        I activity = getActivity();
        aVar.getClass();
        if (bundle != null) {
            final long[] longArray = bundle.getLongArray("ContextualCheckboxHelperselectedIds");
            if (longArray != null) {
                if (longArray.length == 0) {
                    lArr = org.apache.commons.lang3.b.a;
                } else {
                    Long[] lArr2 = new Long[longArray.length];
                    Arrays.setAll(lArr2, new IntFunction() { // from class: org.apache.commons.lang3.a
                        @Override // java.util.function.IntFunction
                        public final Object apply(int i) {
                            return Long.valueOf(longArray[i]);
                        }
                    });
                    lArr = lArr2;
                }
                aVar.a = new ArrayList(Arrays.asList(lArr));
            }
            if (bundle.getBoolean("ContextualCheckboxHelperinActionMode", false)) {
                activity.startActionMode(aVar);
            }
        }
        return viewOnCreateView;
    }

    @Override // com.quizlet.features.infra.legacyadapter.RecyclerViewFragment, androidx.fragment.app.Fragment
    public final void onSaveInstanceState(Bundle bundle) {
        super.onSaveInstanceState(bundle);
        com.quizlet.features.infra.legacyadapter.helper.a aVar = this.v;
        bundle.putLongArray("ContextualCheckboxHelperselectedIds", AbstractC3543u4.b(aVar.a));
        bundle.putBoolean("ContextualCheckboxHelperinActionMode", aVar.b != null);
    }
}

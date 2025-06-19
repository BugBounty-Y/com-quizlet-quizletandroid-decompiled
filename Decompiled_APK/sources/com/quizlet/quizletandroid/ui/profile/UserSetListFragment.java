package com.quizlet.quizletandroid.ui.profile;

import android.content.Context;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;
import androidx.recyclerview.widget.AbstractC1361d0;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3537t4;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3707q6;
import com.google.android.gms.measurement.internal.Z;
import com.quizlet.db.data.models.base.DBModel;
import com.quizlet.db.data.models.persisted.DBStudySet;
import com.quizlet.db.data.models.persisted.base.Models;
import com.quizlet.db.data.models.persisted.fields.DBGroupSetFields;
import com.quizlet.partskit.widgets.icon.IconFontTextView;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.ui.base.DataSourceRecyclerViewFragment;
import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import kotlin.collections.C;
import kotlin.collections.CollectionsKt;
import kotlin.collections.M;
import kotlin.text.Regex;

/* loaded from: classes3.dex */
public class UserSetListFragment extends DataSourceRecyclerViewFragment<DBStudySet, com.quizlet.infra.legacysyncengine.datasources.o, com.quizlet.features.infra.legacyadapter.e> {
    public com.quizlet.features.infra.legacyadapter.e A;
    public WeakReference t;
    public androidx.work.impl.model.n u;
    public com.quizlet.infra.legacysyncengine.net.c v;
    public com.quizlet.features.setpage.utils.setpermissions.a w;
    public com.quizlet.features.setpage.upsell.a x;
    public com.quizlet.offline.managers.b y;
    public final com.quizlet.login.common.interactors.d z = new com.quizlet.login.common.interactors.d(this, 6);

    @Override // com.quizlet.baseui.base.BaseFragment
    public final String N() {
        return "UserSetListFragment";
    }

    @Override // com.quizlet.features.infra.legacyadapter.RecyclerViewFragment
    public final AbstractC1361d0 Q() {
        com.quizlet.features.infra.legacyadapter.e eVar = new com.quizlet.features.infra.legacyadapter.e(null, this.z, this.y);
        this.A = eVar;
        return eVar;
    }

    @Override // com.quizlet.features.infra.legacyadapter.RecyclerViewFragment
    public final View R(ViewGroup viewGroup) {
        View viewC = Z.c(viewGroup, R.layout.view_empty_viewable_list, viewGroup, false);
        ((IconFontTextView) viewC.findViewById(R.id.empty_icon)).setIcon("flashcards");
        TextView textView = (TextView) viewC.findViewById(R.id.empty_message);
        v vVar = (v) this.t.get();
        if (vVar != null) {
            ProfileFragment profileFragment = (ProfileFragment) vVar;
            if (profileFragment.X().C(profileFragment.W())) {
                textView.setText(R.string.own_empty_profile_sets);
                return viewC;
            }
        }
        textView.setText(R.string.empty_list_sets);
        return viewC;
    }

    @Override // com.quizlet.features.infra.legacyadapter.RecyclerViewFragment
    public final boolean T(int i) {
        return true;
    }

    @Override // com.quizlet.features.infra.legacyadapter.RecyclerViewFragment
    public final boolean V() {
        return getActivity() instanceof ProfileActivity;
    }

    @Override // com.quizlet.quizletandroid.ui.base.DataSourceRecyclerViewFragment
    public final void W(List list) {
        Set setA0;
        DBModel.Companion.sortReverse(list);
        HashSet hashSet = new HashSet();
        ArrayList arrayList = new ArrayList();
        Iterator it2 = list.iterator();
        while (it2.hasNext()) {
            DBStudySet dBStudySet = (DBStudySet) it2.next();
            if (this.u.g(dBStudySet)) {
                hashSet.add(Long.valueOf(dBStudySet.getId()));
            }
            if (dBStudySet.getIsCreated()) {
                arrayList.add(dBStudySet);
            }
        }
        com.quizlet.infra.legacysyncengine.net.c cVar = this.v;
        String string = this.x.a.getString("group_id", "");
        String str = string != null ? string : "";
        if (str.length() > 0) {
            List listG = new Regex(",").g(0, str);
            ArrayList arrayList2 = new ArrayList(C.q(listG, 10));
            Iterator it3 = listG.iterator();
            while (it3.hasNext()) {
                arrayList2.add(Long.valueOf(Long.parseLong((String) it3.next())));
            }
            setA0 = CollectionsKt.A0(arrayList2);
        } else {
            setA0 = M.a;
        }
        if (hashSet.size() > 0 && setA0.size() > 0) {
            com.quizlet.infra.legacysyncengine.orm.b bVar = new com.quizlet.infra.legacysyncengine.orm.b(Models.GROUP_SET);
            bVar.c(DBGroupSetFields.SET, hashSet, null);
            bVar.c(DBGroupSetFields.GROUP, setA0, null);
            cVar.c(bVar.a(), AbstractC3537t4.g(com.quizlet.infra.legacysyncengine.net.b.b));
        }
        this.A.g(arrayList);
    }

    @Override // com.quizlet.quizletandroid.ui.base.DataSourceRecyclerViewFragment
    public final boolean X() {
        v vVar = (v) this.t.get();
        if (vVar == null) {
            return false;
        }
        ProfileFragment profileFragment = (ProfileFragment) vVar;
        return !profileFragment.X().C(profileFragment.W());
    }

    @Override // com.quizlet.baseui.base.BaseFragment, com.quizlet.baseui.di.BaseDaggerFragment, androidx.fragment.app.Fragment
    public final void onAttach(Context context) {
        super.onAttach(context);
        this.t = new WeakReference((v) AbstractC3707q6.b(this, v.class));
    }
}

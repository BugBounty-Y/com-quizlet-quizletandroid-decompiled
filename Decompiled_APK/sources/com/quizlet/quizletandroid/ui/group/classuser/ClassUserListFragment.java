package com.quizlet.quizletandroid.ui.group.classuser;

import android.os.Bundle;
import android.view.View;
import android.view.ViewGroup;
import androidx.core.view.L;
import androidx.core.view.V;
import androidx.lifecycle.B0;
import androidx.lifecycle.viewmodel.c;
import androidx.lifecycle.y0;
import androidx.recyclerview.widget.AbstractC1361d0;
import com.google.android.gms.internal.mlkit_vision_camera.C1;
import com.google.android.gms.measurement.internal.Z;
import com.quizlet.data.repository.metering.j;
import com.quizlet.db.data.caches.UserInfoCache;
import com.quizlet.db.data.models.base.DBModel;
import com.quizlet.db.data.models.persisted.DBGroupMembership;
import com.quizlet.db.data.models.persisted.DBUser;
import com.quizlet.features.infra.legacyadapter.e;
import com.quizlet.infra.legacysyncengine.managers.d;
import com.quizlet.infra.legacysyncengine.net.f;
import com.quizlet.quizletandroid.R;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.WeakHashMap;
import kotlin.jvm.internal.C4950i;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.K;

/* loaded from: classes3.dex */
public class ClassUserListFragment extends Hilt_ClassUserListFragment<DBGroupMembership> {
    public UserInfoCache A;
    public e C;
    public DBGroupMembership D;
    public com.quizlet.quizletandroid.ui.group.classuser.viewmodel.a F;
    public f y;
    public d z;
    public final com.quizlet.login.authentication.login.a B = new com.quizlet.login.authentication.login.a(this, 8);
    public boolean E = false;

    @Override // com.quizlet.baseui.base.BaseFragment
    public final String N() {
        return "ClassUserListFragment";
    }

    @Override // com.quizlet.features.infra.legacyadapter.RecyclerViewFragment
    public final AbstractC1361d0 Q() {
        e eVar = new e(null, this.B, null);
        this.C = eVar;
        return eVar;
    }

    @Override // com.quizlet.features.infra.legacyadapter.RecyclerViewFragment
    public final View R(ViewGroup viewGroup) {
        return !this.A.b() ? Z.c(viewGroup, R.layout.view_class_user_list_logged_out_empty, viewGroup, false) : new View(super.getContext());
    }

    @Override // com.quizlet.features.infra.legacyadapter.RecyclerViewFragment
    public final View S(ViewGroup viewGroup) {
        return !this.A.b() ? Z.c(viewGroup, R.layout.view_class_user_list_logged_out_empty, viewGroup, false) : Z.c(viewGroup, R.layout.view_class_user_list_generic_error_empty, viewGroup, false);
    }

    @Override // com.quizlet.features.infra.legacyadapter.RecyclerViewFragment
    public final boolean T(int i) {
        return this.C.d(i) != null;
    }

    @Override // com.quizlet.quizletandroid.ui.base.ViewModelDataSourceRecyclerViewFragment
    public final void W(List list) {
        ArrayList arrayList = new ArrayList(list);
        ArrayList arrayList2 = new ArrayList();
        DBModel.Companion.sort(arrayList);
        Iterator it2 = arrayList.iterator();
        while (it2.hasNext()) {
            DBGroupMembership dBGroupMembership = (DBGroupMembership) it2.next();
            DBUser dBUser = this.z.r;
            if (dBUser != null && dBGroupMembership.getUser().getId() == dBUser.getId() && !dBGroupMembership.getUser().getImageUrl().equals(dBUser.getImageUrl())) {
                dBGroupMembership.getUser().setImageUrl(dBUser.getImageUrl());
            }
            if (dBGroupMembership.getLevel() >= 1 && dBGroupMembership.getUser() != null) {
                arrayList2.add(dBGroupMembership.getUser());
            }
            if (dBGroupMembership.getUserId() == this.A.getPersonId()) {
                this.D = dBGroupMembership;
            }
        }
        DBGroupMembership dBGroupMembership2 = this.D;
        if (dBGroupMembership2 == null || !dBGroupMembership2.isInvolved()) {
            arrayList2 = new ArrayList();
        }
        this.C.g(arrayList2);
    }

    @Override // com.quizlet.quizletandroid.ui.base.ViewModelDataSourceRecyclerViewFragment
    public final com.quizlet.quizletandroid.ui.base.viewmodel.a X() {
        B0 store = getViewModelStore();
        y0 factory = super.getDefaultViewModelProviderFactory();
        c defaultCreationExtras = requireParentFragment().getDefaultViewModelCreationExtras();
        Intrinsics.checkNotNullParameter(store, "store");
        Intrinsics.checkNotNullParameter(factory, "factory");
        Intrinsics.checkNotNullParameter(defaultCreationExtras, "defaultCreationExtras");
        j jVar = new j(store, factory, defaultCreationExtras);
        Intrinsics.checkNotNullParameter(com.quizlet.quizletandroid.ui.group.classuser.viewmodel.a.class, "modelClass");
        Intrinsics.checkNotNullParameter(com.quizlet.quizletandroid.ui.group.classuser.viewmodel.a.class, "<this>");
        C4950i modelClass = K.a(com.quizlet.quizletandroid.ui.group.classuser.viewmodel.a.class);
        Intrinsics.checkNotNullParameter(modelClass, "modelClass");
        Intrinsics.checkNotNullParameter(modelClass, "modelClass");
        String strB = C1.b(modelClass);
        if (strB == null) {
            throw new IllegalArgumentException("Local and anonymous classes can not be ViewModels");
        }
        com.quizlet.quizletandroid.ui.group.classuser.viewmodel.a aVar = (com.quizlet.quizletandroid.ui.group.classuser.viewmodel.a) jVar.e(modelClass, "androidx.lifecycle.ViewModelProvider.DefaultKey:".concat(strB));
        this.F = aVar;
        return aVar;
    }

    @Override // com.quizlet.quizletandroid.ui.base.ViewModelDataSourceRecyclerViewFragment
    public final void Y(com.quizlet.infra.legacysyncengine.net.request.c cVar) {
        if (cVar.b()) {
            return;
        }
        this.E = true;
        if (this.A.b()) {
            if (this.C.c.size() != 0) {
                e eVar = this.C;
                eVar.notifyItemChanged(eVar.f.h());
                return;
            }
            e eVar2 = this.C;
            a aVar = new a(this);
            LinkedHashMap linkedHashMap = eVar2.c;
            if (linkedHashMap.containsKey(Integer.valueOf(R.layout.group_info_footer))) {
                throw new IllegalArgumentException("Cannot add multiple footers with same layout");
            }
            linkedHashMap.put(Integer.valueOf(R.layout.group_info_footer), aVar);
            eVar2.notifyDataSetChanged();
            this.l.b(true);
        }
    }

    @Override // com.quizlet.quizletandroid.ui.base.ViewModelDataSourceRecyclerViewFragment
    public final boolean a0() {
        return true;
    }

    @Override // com.quizlet.quizletandroid.ui.base.ViewModelDataSourceRecyclerViewFragment, com.quizlet.features.infra.legacyadapter.RecyclerViewFragment, com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final void onViewCreated(View view, Bundle bundle) {
        super.onViewCreated(view, bundle);
        ((com.quizlet.features.infra.legacyadapter.databinding.a) J()).f.setClipToPadding(false);
        com.quizlet.features.infra.legacyadapter.databinding.a aVar = (com.quizlet.features.infra.legacyadapter.databinding.a) J();
        com.quizlet.infra.legacysyncengine.models.serializers.a aVar2 = new com.quizlet.infra.legacysyncengine.models.serializers.a(21);
        WeakHashMap weakHashMap = V.a;
        L.m(aVar.f, aVar2);
    }

    @Override // dagger.hilt.android.internal.migration.a
    public final boolean u() {
        return this.x;
    }
}

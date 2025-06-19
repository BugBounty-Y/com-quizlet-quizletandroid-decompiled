package com.quizlet.features.infra.legacyadapter;

import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.emoji2.text.n;
import androidx.recyclerview.widget.AbstractC1361d0;
import androidx.recyclerview.widget.F0;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3299x6;
import com.google.android.gms.internal.mlkit_vision_barcode.F6;
import com.google.android.gms.measurement.internal.Z;
import com.quizlet.db.data.models.base.DBModel;
import com.quizlet.db.data.models.persisted.DBFolder;
import com.quizlet.db.data.models.persisted.DBGroup;
import com.quizlet.db.data.models.persisted.DBGroupMembership;
import com.quizlet.db.data.models.persisted.DBSchool;
import com.quizlet.db.data.models.persisted.DBStudySet;
import com.quizlet.db.data.models.persisted.DBUser;
import com.quizlet.db.data.models.persisted.base.ModelType;
import com.quizlet.db.data.models.persisted.base.Models;
import com.quizlet.features.infra.legacyadapter.common.UserListTitleView;
import com.quizlet.features.infra.legacyadapter.viewholder.k;
import com.quizlet.features.infra.legacyadapter.viewholder.l;
import com.quizlet.features.infra.legacyadapter.viewholder.m;
import com.quizlet.features.infra.models.Creator;
import com.quizlet.offline.managers.i;
import com.quizlet.partskit.widgets.QTextView;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.ui.group.classuser.ClassUserListFragment;
import io.reactivex.rxjava3.core.p;
import io.reactivex.rxjava3.internal.operators.observable.C4887f;
import io.reactivex.rxjava3.internal.operators.observable.W;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class e extends AbstractC1361d0 {
    public final com.lyft.android.scissors.b a;
    public final com.quizlet.features.infra.legacyadapter.helper.a b;
    public final LinkedHashMap c = new LinkedHashMap();
    public final com.quizlet.offline.managers.b d;
    public final HashMap e;
    public final com.google.mlkit.vision.documentscanner.internal.c f;
    public io.reactivex.rxjava3.disposables.d g;
    public AtomicReference h;

    public e(com.quizlet.features.infra.legacyadapter.helper.a aVar, d dVar, com.quizlet.offline.managers.b bVar) {
        HashMap map = new HashMap();
        this.e = map;
        this.f = new com.google.mlkit.vision.documentscanner.internal.c();
        n nVar = io.reactivex.rxjava3.internal.functions.d.b;
        this.g = new io.reactivex.rxjava3.disposables.d(nVar, 0);
        this.h = new io.reactivex.rxjava3.disposables.d(nVar, 0);
        this.b = aVar;
        this.a = new com.lyft.android.scissors.b(dVar, 17);
        this.d = bVar;
        ModelType<DBStudySet> modelType = Models.STUDY_SET;
        int i = k.g;
        map.put(modelType, Integer.valueOf(R.layout.nav2_listitem_set));
        ModelType<DBGroup> modelType2 = Models.GROUP;
        int i2 = com.quizlet.features.infra.legacyadapter.viewholder.g.b;
        map.put(modelType2, Integer.valueOf(R.layout.nav2_listitem_group));
        ModelType<DBUser> modelType3 = Models.USER;
        int i3 = m.d;
        map.put(modelType3, Integer.valueOf(R.layout.listitem_user));
        ModelType<DBFolder> modelType4 = Models.FOLDER;
        int i4 = com.quizlet.features.infra.legacyadapter.viewholder.e.f;
        map.put(modelType4, Integer.valueOf(R.layout.nav2_listitem_folder));
        if (bVar != null) {
            i iVar = (i) bVar;
            com.quizlet.remote.connectivity.a aVar2 = ((com.quizlet.remote.connectivity.b) iVar.b).a;
            W wS = new C4887f(aVar2.a.q(com.quizlet.offline.managers.e.f), 1).s(iVar.c);
            Intrinsics.checkNotNullExpressionValue(wS, "observeOn(...)");
            this.h = (AtomicReference) wS.u(new com.quizlet.billing.subscriptions.a(this, 4), io.reactivex.rxjava3.internal.functions.d.e, io.reactivex.rxjava3.internal.functions.d.c);
        }
    }

    public final DBModel d(int i) {
        if (i >= this.f.h()) {
            return null;
        }
        com.quizlet.features.infra.legacyadapter.section.a aVarI = this.f.i(i);
        if (this.f.j(aVarI) >= 0) {
            return (DBModel) aVarI.b(i - this.f.j(aVarI));
        }
        return null;
    }

    public final long f(int i) {
        Iterator it2 = ((ArrayList) this.f.b).iterator();
        int i2 = 0;
        while (true) {
            if (!it2.hasNext()) {
                i2 = -1;
                break;
            }
            com.quizlet.features.infra.legacyadapter.section.a aVar = (com.quizlet.features.infra.legacyadapter.section.a) it2.next();
            if (i < aVar.a()) {
                break;
            }
            i -= aVar.a();
            i2++;
        }
        return (i2 * 3) + 100;
    }

    public final void g(List list) {
        if (list == null) {
            return;
        }
        ((ArrayList) this.f.b).clear();
        com.google.mlkit.vision.documentscanner.internal.c cVar = this.f;
        ((ArrayList) cVar.b).add(new com.quizlet.features.infra.legacyadapter.section.a(list));
        notifyDataSetChanged();
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final int getItemCount() {
        return this.c.size() + this.f.h();
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final long getItemId(int i) {
        long jF;
        long j;
        DBModel dBModelD = d(i);
        if (dBModelD != null) {
            return dBModelD.getLocalId();
        }
        int itemViewType = getItemViewType(i);
        int i2 = com.quizlet.features.infra.legacyadapter.viewholder.h.d;
        if (itemViewType == R.layout.listitem_section_header) {
            return f(i);
        }
        int i3 = com.quizlet.features.infra.legacyadapter.viewholder.b.a;
        if (itemViewType == R.layout.listitem_empty_filter) {
            jF = f(i);
            j = 2;
        } else {
            int i4 = l.d;
            if (itemViewType != R.layout.listitem_top_button) {
                return itemViewType;
            }
            jF = f(i);
            j = 1;
        }
        return jF + j;
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final int getItemViewType(int i) {
        com.google.mlkit.vision.documentscanner.internal.c cVar = this.f;
        int iH = cVar.h();
        if (i >= iH) {
            return ((Integer) new ArrayList(this.c.keySet()).get(i - iH)).intValue();
        }
        cVar.i(i);
        cVar.i(i);
        cVar.i(i);
        DBModel dBModelD = d(i);
        if (dBModelD == null) {
            int i2 = com.quizlet.features.infra.legacyadapter.viewholder.h.d;
            return R.layout.listitem_section_header;
        }
        if (Models.FOLDER.equals(dBModelD.getModelType())) {
            int i3 = com.quizlet.features.infra.legacyadapter.viewholder.e.f;
            return R.layout.nav2_listitem_folder;
        }
        if (Models.GROUP.equals(dBModelD.getModelType())) {
            int i4 = com.quizlet.features.infra.legacyadapter.viewholder.g.b;
            return R.layout.nav2_listitem_group;
        }
        if (!Models.STUDY_SET.equals(dBModelD.getModelType())) {
            return ((Integer) this.e.get(dBModelD.getModelType())).intValue();
        }
        int i5 = k.g;
        return R.layout.nav2_listitem_set;
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final void onBindViewHolder(F0 f0, int i) {
        onBindViewHolder(f0, i, Collections.EMPTY_LIST);
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final F0 onCreateViewHolder(ViewGroup viewGroup, int i) {
        int i2 = com.quizlet.features.infra.legacyadapter.viewholder.c.a;
        int i3 = 0;
        if (i == R.layout.listitem_filter) {
            View itemView = Z.c(viewGroup, R.layout.listitem_filter, viewGroup, false);
            Intrinsics.checkNotNullParameter(itemView, "itemView");
            com.quizlet.features.infra.legacyadapter.viewholder.c cVar = new com.quizlet.features.infra.legacyadapter.viewholder.c(itemView);
            kotlin.l.b(new com.quizlet.features.infra.legacyadapter.viewholder.a(itemView, 1));
            return cVar;
        }
        int i4 = com.quizlet.features.infra.legacyadapter.viewholder.b.a;
        if (i == R.layout.listitem_empty_filter) {
            View itemView2 = Z.c(viewGroup, R.layout.listitem_empty_filter, viewGroup, false);
            Intrinsics.checkNotNullParameter(itemView2, "itemView");
            com.quizlet.features.infra.legacyadapter.viewholder.b bVar = new com.quizlet.features.infra.legacyadapter.viewholder.b(itemView2);
            kotlin.l.b(new com.quizlet.features.infra.legacyadapter.viewholder.a(itemView2, i3));
            return bVar;
        }
        int i5 = l.d;
        if (i == R.layout.listitem_top_button) {
            return new l(Z.c(viewGroup, R.layout.listitem_top_button, viewGroup, false));
        }
        int i6 = k.g;
        if (i == R.layout.nav2_listitem_set) {
            View viewC = Z.c(viewGroup, R.layout.nav2_listitem_set, viewGroup, false);
            if (AbstractC3299x6.a(viewC, false)) {
                viewC.requestLayout();
            }
            return new k(viewC);
        }
        int i7 = com.quizlet.features.infra.legacyadapter.viewholder.g.b;
        if (i == R.layout.nav2_listitem_group) {
            View viewC2 = Z.c(viewGroup, R.layout.nav2_listitem_group, viewGroup, false);
            if (AbstractC3299x6.a(viewC2, false)) {
                viewC2.requestLayout();
            }
            return new com.quizlet.features.infra.legacyadapter.viewholder.g(viewC2);
        }
        int i8 = m.d;
        if (i == R.layout.listitem_user) {
            View itemView3 = Z.c(viewGroup, R.layout.listitem_user, viewGroup, false);
            Intrinsics.checkNotNullParameter(itemView3, "itemView");
            return new m(itemView3);
        }
        int i9 = com.quizlet.features.infra.legacyadapter.viewholder.e.f;
        if (i == R.layout.nav2_listitem_folder) {
            View viewC3 = Z.c(viewGroup, R.layout.nav2_listitem_folder, viewGroup, false);
            if (AbstractC3299x6.a(viewC3, false)) {
                viewC3.requestLayout();
            }
            return new com.quizlet.features.infra.legacyadapter.viewholder.e(viewC3);
        }
        int i10 = com.quizlet.features.infra.legacyadapter.viewholder.h.d;
        if (i != R.layout.listitem_section_header) {
            return new c(Z.c(viewGroup, i, viewGroup, false));
        }
        View view = Z.c(viewGroup, R.layout.listitem_section_header, viewGroup, false);
        Intrinsics.checkNotNullParameter(view, "view");
        return new com.quizlet.features.infra.legacyadapter.viewholder.h(view);
    }

    /* JADX WARN: Multi-variable type inference failed */
    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final void onBindViewHolder(F0 f0, final int i, List list) {
        Long singleFieldIdentityValue;
        if (f0 instanceof com.quizlet.features.infra.legacyadapter.viewholder.i) {
            com.quizlet.features.infra.legacyadapter.viewholder.i iVar = (com.quizlet.features.infra.legacyadapter.viewholder.i) f0;
            iVar.a(new a(this, i, 0));
            iVar.b(new View.OnLongClickListener() { // from class: com.quizlet.features.infra.legacyadapter.b
                @Override // android.view.View.OnLongClickListener
                public final boolean onLongClick(View view) {
                    e eVar = this.a;
                    int i2 = i;
                    DBModel dBModelD = eVar.d(i2);
                    return dBModelD != null && eVar.a.b(view, i2, dBModelD);
                }
            });
        }
        if (f0 instanceof com.quizlet.features.infra.legacyadapter.viewholder.c) {
            this.f.i(i).getClass();
            throw new ClassCastException();
        }
        if (f0 instanceof com.quizlet.features.infra.legacyadapter.viewholder.b) {
            this.f.i(i).getClass();
            throw new ClassCastException();
        }
        if (f0 instanceof l) {
            this.f.i(i).getClass();
            throw new ClassCastException();
        }
        if (f0 instanceof com.quizlet.features.infra.legacyadapter.viewholder.h) {
            ((com.quizlet.features.infra.legacyadapter.viewholder.h) f0).c((com.quizlet.features.infra.legacyadapter.section.b) this.f.i(i));
            return;
        }
        if (i >= this.f.h()) {
            ClassUserListFragment classUserListFragment = ((com.quizlet.quizletandroid.ui.group.classuser.a) this.c.get(Integer.valueOf(getItemViewType(i)))).a;
            classUserListFragment.getClass();
            Button button = (Button) f0.itemView.findViewById(R.id.join_drop_class);
            button.setVisibility(0);
            DBGroupMembership dBGroupMembership = classUserListFragment.D;
            int level = dBGroupMembership != null ? dBGroupMembership.getLevel() : classUserListFragment.E ? -3 : -4;
            if (level == -3 || level == -2 || level == -1) {
                button.setText(R.string.join_class);
            } else if (level != 0) {
                button.setVisibility(8);
            } else {
                button.setText(R.string.cancel_request);
            }
            button.setOnClickListener(new a(classUserListFragment, level, 1));
            return;
        }
        DBModel dBModelD = d(i);
        if (dBModelD != null) {
            com.quizlet.features.infra.legacyadapter.helper.a aVar = this.b;
            boolean zContains = (aVar == null || (singleFieldIdentityValue = dBModelD.getIdentity().getSingleFieldIdentityValue()) == null) ? false : aVar.a.contains(singleFieldIdentityValue);
            boolean z = true;
            if (f0 instanceof k) {
                if (!(dBModelD instanceof DBStudySet)) {
                    throw new IllegalStateException("Unexpected model type: " + dBModelD.getModelType());
                }
                k kVar = (k) f0;
                DBStudySet studySet = (DBStudySet) dBModelD;
                p isAvailable = p.f(Boolean.TRUE);
                com.quizlet.offline.managers.b bVar = this.d;
                if (bVar != null) {
                    i iVar2 = (i) bVar;
                    if (!iVar2.i) {
                        Intrinsics.checkNotNullParameter(studySet, "studySet");
                        Intrinsics.checkNotNullParameter(studySet, "studySet");
                        long id = studySet.getId();
                        DBUser creator = studySet.getCreator();
                        isAvailable = iVar2.c(id, creator != null ? creator.getIsVerified() : false);
                        z = false;
                    }
                }
                if (list != null && !list.isEmpty()) {
                    if (list.contains("UPDATE_OFFLINE_PAYLOAD")) {
                        kVar.h(isAvailable);
                        return;
                    }
                    return;
                } else {
                    this.f.i(0);
                    kVar.getClass();
                    Intrinsics.checkNotNullParameter(studySet, "studySet");
                    Intrinsics.checkNotNullParameter(isAvailable, "isAvailable");
                    k.f(kVar, studySet, zContains, isAvailable, z);
                    return;
                }
            }
            if (f0 instanceof com.quizlet.features.infra.legacyadapter.viewholder.g) {
                com.quizlet.features.infra.legacyadapter.viewholder.g gVar = (com.quizlet.features.infra.legacyadapter.viewholder.g) f0;
                DBGroup group = (DBGroup) dBModelD;
                gVar.getClass();
                Intrinsics.checkNotNullParameter(group, "group");
                Intrinsics.checkNotNullParameter(group, "<this>");
                long id2 = group.getId();
                String title = group.getTitle();
                Intrinsics.checkNotNullExpressionValue(title, "getTitle(...)");
                DBSchool school = group.getSchool();
                String schoolString = school != null ? school.getSchoolString() : null;
                com.quizlet.features.infra.models.group.a groupData = new com.quizlet.features.infra.models.group.a(id2, title, schoolString);
                Intrinsics.checkNotNullParameter(groupData, "groupData");
                com.quizlet.features.infra.legacyadapter.databinding.f fVar = gVar.a;
                QTextView listitemGroupName = (QTextView) fVar.e;
                Intrinsics.checkNotNullExpressionValue(listitemGroupName, "listitemGroupName");
                listitemGroupName.setText(title);
                QTextView listitemGroupDetailSchool = (QTextView) fVar.d;
                Intrinsics.checkNotNullExpressionValue(listitemGroupDetailSchool, "listitemGroupDetailSchool");
                listitemGroupDetailSchool.setText(schoolString);
                QTextView listitemGroupDetailSchool2 = (QTextView) fVar.d;
                Intrinsics.checkNotNullExpressionValue(listitemGroupDetailSchool2, "listitemGroupDetailSchool");
                if (schoolString != null && schoolString.length() != 0) {
                    z = false;
                }
                com.facebook.appevents.cloudbridge.c.c(listitemGroupDetailSchool2, z);
                int i2 = zContains ? R.drawable.accent_rectangle_border : 0;
                ConstraintLayout listitemGroupCardLayout = (ConstraintLayout) fVar.c;
                Intrinsics.checkNotNullExpressionValue(listitemGroupCardLayout, "listitemGroupCardLayout");
                listitemGroupCardLayout.setBackgroundResource(i2);
                return;
            }
            if (f0 instanceof m) {
                m mVar = (m) f0;
                DBUser user = (DBUser) dBModelD;
                mVar.getClass();
                Intrinsics.checkNotNullParameter(user, "user");
                UserListTitleView userDetailsListItem = ((com.quizlet.features.infra.legacyadapter.databinding.d) mVar.e()).b;
                Intrinsics.checkNotNullExpressionValue(userDetailsListItem, "userDetailsListItem");
                userDetailsListItem.setUser(user);
                return;
            }
            if (f0 instanceof com.quizlet.features.infra.legacyadapter.viewholder.e) {
                if (!(dBModelD instanceof DBFolder)) {
                    throw new IllegalStateException("Unexpected model type: " + dBModelD.getModelType());
                }
                com.quizlet.features.infra.legacyadapter.viewholder.e eVar = (com.quizlet.features.infra.legacyadapter.viewholder.e) f0;
                DBFolder folder = (DBFolder) dBModelD;
                eVar.getClass();
                Intrinsics.checkNotNullParameter(folder, "folder");
                com.quizlet.features.infra.models.folders.a folderData = F6.b(folder);
                Intrinsics.checkNotNullParameter(folderData, "folderData");
                Creator creator2 = folderData.d;
                if (creator2 != null) {
                    eVar.f(folderData.b, creator2.b, creator2.d, creator2.c, creator2.e, zContains);
                    return;
                }
                if (folderData.c != eVar.h().e.getPersonId()) {
                    eVar.g(folderData.b, zContains);
                    return;
                }
                com.quizlet.infra.legacysyncengine.managers.d dVarH = eVar.h();
                DBUser dBUser = dVarH.r;
                String username = dBUser != null ? dBUser.getUsername() : dVarH.e.getUsername();
                Intrinsics.checkNotNullExpressionValue(username, "getLoggedInUsername(...)");
                com.quizlet.infra.legacysyncengine.managers.d dVarH2 = eVar.h();
                DBUser dBUser2 = dVarH2.r;
                int creatorBadgeText = dBUser2 != null ? dBUser2.getCreatorBadgeText() : dVarH2.e.getUserBadgeStringResId();
                com.quizlet.infra.legacysyncengine.managers.d dVarH3 = eVar.h();
                DBUser dBUser3 = dVarH3.r;
                String imageUrl = dBUser3 != null ? dBUser3.getImageUrl() : dVarH3.e.getProfileImage();
                DBUser dBUser4 = eVar.h().r;
                eVar.f(folderData.b, username, creatorBadgeText, imageUrl, dBUser4 != null ? dBUser4.getIsVerified() : false, zContains);
            }
        }
    }
}

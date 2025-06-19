package com.quizlet.quizletandroid.ui.group;

import android.content.Context;
import android.content.Intent;
import android.content.res.Resources;
import android.os.Bundle;
import android.view.ActionMode;
import android.view.LayoutInflater;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import androidx.appcompat.app.AbstractActivityC0055k;
import androidx.appcompat.widget.Toolbar;
import androidx.coordinatorlayout.widget.CoordinatorLayout;
import androidx.core.app.U;
import androidx.core.view.L;
import androidx.core.view.V;
import androidx.fragment.app.AbstractC1136h0;
import androidx.fragment.app.I;
import com.braze.requests.framework.m;
import com.google.android.gms.internal.mlkit_vision_barcode.I6;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.google.android.material.appbar.AppBarLayout;
import com.google.android.material.appbar.CollapsingToolbarLayout;
import com.quizlet.api.IQuizletApiClient;
import com.quizlet.db.data.caches.UserInfoCache;
import com.quizlet.db.data.models.persisted.DBGroup;
import com.quizlet.db.data.models.persisted.DBGroupMembership;
import com.quizlet.db.data.models.persisted.DBUser;
import com.quizlet.db.data.models.persisted.base.ModelType;
import com.quizlet.db.data.models.persisted.base.Models;
import com.quizlet.db.data.models.persisted.fields.DBGroupFields;
import com.quizlet.db.data.models.persisted.fields.DBGroupMembershipFields;
import com.quizlet.db.data.orm.Relationship;
import com.quizlet.eventlogger.EventLogger;
import com.quizlet.eventlogger.EventLoggerExt;
import com.quizlet.explanations.databinding.n;
import com.quizlet.partskit.widgets.QButton;
import com.quizlet.partskit.widgets.QTabLayout;
import com.quizlet.partskit.widgets.QTextView;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.databinding.H;
import com.quizlet.quizletandroid.ui.common.views.ToggleSwipeableViewPager;
import com.quizlet.quizletandroid.ui.group.addclassset.AddClassSetActivity;
import com.quizlet.quizletandroid.ui.joincontenttofolder.JoinContentToFolderActivity;
import com.quizlet.uicommon.ui.common.dialogs.e;
import com.quizlet.uicommon.ui.common.dialogs.k;
import io.reactivex.rxjava3.core.o;
import io.reactivex.rxjava3.core.p;
import io.reactivex.rxjava3.internal.operators.observable.J;
import io.reactivex.rxjava3.internal.operators.observable.W;
import java.util.WeakHashMap;
import kotlin.Metadata;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.l;
import kotlin.u;

@Metadata
/* loaded from: classes3.dex */
public final class GroupFragment extends Hilt_GroupFragment<H> implements ActionMode.Callback, com.quizlet.baseui.interfaces.a {
    public static final String M;
    public static final int V;
    public static final int[] W;
    public final u A;
    public final u B;
    public final u C;
    public final u D;
    public final u E;
    public DBGroup F;
    public String G;
    public DBGroupMembership H;
    public boolean I;
    public boolean J;
    public boolean K;
    public n L;
    public com.quizlet.infra.legacysyncengine.net.c j;
    public EventLogger k;
    public androidx.work.impl.model.c l;
    public com.quizlet.infra.legacysyncengine.managers.h m;
    public IQuizletApiClient n;
    public com.quizlet.infra.legacysyncengine.net.f o;
    public o p;
    public o q;
    public com.quizlet.infra.legacysyncengine.managers.d r;
    public UserInfoCache s;
    public com.quizlet.shared.usecase.srs.a t;
    public com.google.android.material.floatingactionbutton.c u;
    public com.quizlet.shared.usecase.srs.a v;
    public com.quizlet.data.interactor.achievements.f w;
    public com.quizlet.features.notes.a x;
    public com.quizlet.data.repository.user.a y;
    public com.quizlet.quizletandroid.ui.common.adapter.c z;

    static {
        Intrinsics.checkNotNullExpressionValue("GroupFragment", "getSimpleName(...)");
        M = "GroupFragment";
        V = R.menu.group_menu;
        W = new int[]{R.string.sets_tab_header, R.string.members_tab_header};
    }

    public GroupFragment() {
        final int i = 0;
        this.A = l.b(new Function0(this) { // from class: com.quizlet.quizletandroid.ui.group.c
            public final /* synthetic */ GroupFragment b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function0
            public final Object invoke() {
                GroupFragment groupFragment = this.b;
                switch (i) {
                    case 0:
                        String str = GroupFragment.M;
                        return Long.valueOf(groupFragment.requireArguments().getLong("KEY_GROUP_CLASS_ID"));
                    case 1:
                        String str2 = GroupFragment.M;
                        return groupFragment.requireArguments().getString("autoJoinCode", "");
                    case 2:
                        String str3 = GroupFragment.M;
                        return Boolean.valueOf(groupFragment.requireArguments().getBoolean("shouldShowJoinButton", false));
                    case 3:
                        String str4 = GroupFragment.M;
                        long jU = groupFragment.U();
                        com.quizlet.infra.legacysyncengine.managers.d dVar = groupFragment.r;
                        if (dVar == null) {
                            Intrinsics.m("loggedInUserManager");
                            throw null;
                        }
                        long personId = dVar.e.getPersonId();
                        com.quizlet.infra.legacysyncengine.net.c cVar = groupFragment.j;
                        if (cVar != null) {
                            return new com.quizlet.quizletandroid.config.features.properties.b(jU, personId, cVar);
                        }
                        Intrinsics.m("loader");
                        throw null;
                    default:
                        String str5 = GroupFragment.M;
                        k kVar = new k(groupFragment.requireContext(), groupFragment.getString(R.string.please_wait));
                        kVar.setCancelable(false);
                        return kVar;
                }
            }
        });
        final int i2 = 1;
        this.B = l.b(new Function0(this) { // from class: com.quizlet.quizletandroid.ui.group.c
            public final /* synthetic */ GroupFragment b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function0
            public final Object invoke() {
                GroupFragment groupFragment = this.b;
                switch (i2) {
                    case 0:
                        String str = GroupFragment.M;
                        return Long.valueOf(groupFragment.requireArguments().getLong("KEY_GROUP_CLASS_ID"));
                    case 1:
                        String str2 = GroupFragment.M;
                        return groupFragment.requireArguments().getString("autoJoinCode", "");
                    case 2:
                        String str3 = GroupFragment.M;
                        return Boolean.valueOf(groupFragment.requireArguments().getBoolean("shouldShowJoinButton", false));
                    case 3:
                        String str4 = GroupFragment.M;
                        long jU = groupFragment.U();
                        com.quizlet.infra.legacysyncengine.managers.d dVar = groupFragment.r;
                        if (dVar == null) {
                            Intrinsics.m("loggedInUserManager");
                            throw null;
                        }
                        long personId = dVar.e.getPersonId();
                        com.quizlet.infra.legacysyncengine.net.c cVar = groupFragment.j;
                        if (cVar != null) {
                            return new com.quizlet.quizletandroid.config.features.properties.b(jU, personId, cVar);
                        }
                        Intrinsics.m("loader");
                        throw null;
                    default:
                        String str5 = GroupFragment.M;
                        k kVar = new k(groupFragment.requireContext(), groupFragment.getString(R.string.please_wait));
                        kVar.setCancelable(false);
                        return kVar;
                }
            }
        });
        final int i3 = 2;
        this.C = l.b(new Function0(this) { // from class: com.quizlet.quizletandroid.ui.group.c
            public final /* synthetic */ GroupFragment b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function0
            public final Object invoke() {
                GroupFragment groupFragment = this.b;
                switch (i3) {
                    case 0:
                        String str = GroupFragment.M;
                        return Long.valueOf(groupFragment.requireArguments().getLong("KEY_GROUP_CLASS_ID"));
                    case 1:
                        String str2 = GroupFragment.M;
                        return groupFragment.requireArguments().getString("autoJoinCode", "");
                    case 2:
                        String str3 = GroupFragment.M;
                        return Boolean.valueOf(groupFragment.requireArguments().getBoolean("shouldShowJoinButton", false));
                    case 3:
                        String str4 = GroupFragment.M;
                        long jU = groupFragment.U();
                        com.quizlet.infra.legacysyncengine.managers.d dVar = groupFragment.r;
                        if (dVar == null) {
                            Intrinsics.m("loggedInUserManager");
                            throw null;
                        }
                        long personId = dVar.e.getPersonId();
                        com.quizlet.infra.legacysyncengine.net.c cVar = groupFragment.j;
                        if (cVar != null) {
                            return new com.quizlet.quizletandroid.config.features.properties.b(jU, personId, cVar);
                        }
                        Intrinsics.m("loader");
                        throw null;
                    default:
                        String str5 = GroupFragment.M;
                        k kVar = new k(groupFragment.requireContext(), groupFragment.getString(R.string.please_wait));
                        kVar.setCancelable(false);
                        return kVar;
                }
            }
        });
        final int i4 = 3;
        this.D = l.b(new Function0(this) { // from class: com.quizlet.quizletandroid.ui.group.c
            public final /* synthetic */ GroupFragment b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function0
            public final Object invoke() {
                GroupFragment groupFragment = this.b;
                switch (i4) {
                    case 0:
                        String str = GroupFragment.M;
                        return Long.valueOf(groupFragment.requireArguments().getLong("KEY_GROUP_CLASS_ID"));
                    case 1:
                        String str2 = GroupFragment.M;
                        return groupFragment.requireArguments().getString("autoJoinCode", "");
                    case 2:
                        String str3 = GroupFragment.M;
                        return Boolean.valueOf(groupFragment.requireArguments().getBoolean("shouldShowJoinButton", false));
                    case 3:
                        String str4 = GroupFragment.M;
                        long jU = groupFragment.U();
                        com.quizlet.infra.legacysyncengine.managers.d dVar = groupFragment.r;
                        if (dVar == null) {
                            Intrinsics.m("loggedInUserManager");
                            throw null;
                        }
                        long personId = dVar.e.getPersonId();
                        com.quizlet.infra.legacysyncengine.net.c cVar = groupFragment.j;
                        if (cVar != null) {
                            return new com.quizlet.quizletandroid.config.features.properties.b(jU, personId, cVar);
                        }
                        Intrinsics.m("loader");
                        throw null;
                    default:
                        String str5 = GroupFragment.M;
                        k kVar = new k(groupFragment.requireContext(), groupFragment.getString(R.string.please_wait));
                        kVar.setCancelable(false);
                        return kVar;
                }
            }
        });
        final int i5 = 4;
        this.E = l.b(new Function0(this) { // from class: com.quizlet.quizletandroid.ui.group.c
            public final /* synthetic */ GroupFragment b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function0
            public final Object invoke() {
                GroupFragment groupFragment = this.b;
                switch (i5) {
                    case 0:
                        String str = GroupFragment.M;
                        return Long.valueOf(groupFragment.requireArguments().getLong("KEY_GROUP_CLASS_ID"));
                    case 1:
                        String str2 = GroupFragment.M;
                        return groupFragment.requireArguments().getString("autoJoinCode", "");
                    case 2:
                        String str3 = GroupFragment.M;
                        return Boolean.valueOf(groupFragment.requireArguments().getBoolean("shouldShowJoinButton", false));
                    case 3:
                        String str4 = GroupFragment.M;
                        long jU = groupFragment.U();
                        com.quizlet.infra.legacysyncengine.managers.d dVar = groupFragment.r;
                        if (dVar == null) {
                            Intrinsics.m("loggedInUserManager");
                            throw null;
                        }
                        long personId = dVar.e.getPersonId();
                        com.quizlet.infra.legacysyncengine.net.c cVar = groupFragment.j;
                        if (cVar != null) {
                            return new com.quizlet.quizletandroid.config.features.properties.b(jU, personId, cVar);
                        }
                        Intrinsics.m("loader");
                        throw null;
                    default:
                        String str5 = GroupFragment.M;
                        k kVar = new k(groupFragment.requireContext(), groupFragment.getString(R.string.please_wait));
                        kVar.setCancelable(false);
                        return kVar;
                }
            }
        });
    }

    @Override // com.quizlet.baseui.base.BaseFragment
    public final String K() {
        String string = getString(R.string.loggingTag_Group);
        Intrinsics.checkNotNullExpressionValue(string, "getString(...)");
        return string;
    }

    @Override // com.quizlet.baseui.base.BaseFragment
    public final Integer M() {
        return Integer.valueOf(V);
    }

    @Override // com.quizlet.baseui.base.BaseFragment
    public final String N() {
        return M;
    }

    @Override // com.quizlet.baseui.base.BaseFragment
    public final androidx.viewbinding.a O(LayoutInflater inflater, ViewGroup viewGroup) {
        Intrinsics.checkNotNullParameter(inflater, "inflater");
        View viewInflate = inflater.inflate(R.layout.group_fragment, viewGroup, false);
        int i = R.id.appbar;
        View viewC = AbstractC3375o2.c(R.id.appbar, viewInflate);
        if (viewC != null) {
            int i2 = R.id.appbar_header;
            FrameLayout frameLayout = (FrameLayout) AbstractC3375o2.c(R.id.appbar_header, viewC);
            if (frameLayout != null) {
                AppBarLayout appBarLayout = (AppBarLayout) viewC;
                i2 = R.id.layout_collapsing_appbar_toolbar;
                if (((CollapsingToolbarLayout) AbstractC3375o2.c(R.id.layout_collapsing_appbar_toolbar, viewC)) != null) {
                    i2 = R.id.tablayout;
                    QTabLayout qTabLayout = (QTabLayout) AbstractC3375o2.c(R.id.tablayout, viewC);
                    if (qTabLayout != null) {
                        i2 = R.id.toolbar;
                        Toolbar toolbar = (Toolbar) AbstractC3375o2.c(R.id.toolbar, viewC);
                        if (toolbar != null) {
                            com.quizlet.features.infra.legacyadapter.databinding.f fVar = new com.quizlet.features.infra.legacyadapter.databinding.f(appBarLayout, frameLayout, qTabLayout, toolbar, 3);
                            CoordinatorLayout coordinatorLayout = (CoordinatorLayout) viewInflate;
                            ToggleSwipeableViewPager toggleSwipeableViewPager = (ToggleSwipeableViewPager) AbstractC3375o2.c(R.id.groupPageViewpager, viewInflate);
                            if (toggleSwipeableViewPager != null) {
                                H h = new H(coordinatorLayout, fVar, coordinatorLayout, toggleSwipeableViewPager);
                                Intrinsics.checkNotNullExpressionValue(h, "inflate(...)");
                                return h;
                            }
                            i = R.id.groupPageViewpager;
                        }
                    }
                }
            }
            throw new NullPointerException("Missing required view with ID: ".concat(viewC.getResources().getResourceName(i2)));
        }
        throw new NullPointerException("Missing required view with ID: ".concat(viewInflate.getResources().getResourceName(i)));
    }

    public final void T(DBGroup dBGroup) throws Resources.NotFoundException {
        if (dBGroup == null) {
            n nVarW = W();
            ((QTextView) nVarW.d).setText((CharSequence) null);
            ((QTextView) nVarW.e).setText((CharSequence) null);
            ((LinearLayout) nVarW.b).setVisibility(8);
            this.G = null;
            ((QTextView) nVarW.f).setText((CharSequence) null);
            return;
        }
        n nVarW2 = W();
        ((LinearLayout) nVarW2.b).setVisibility(0);
        ((QTextView) nVarW2.d).setText(dBGroup.getTitle());
        this.G = dBGroup.getAutoJoinLink();
        ((QTextView) nVarW2.f).setText(getResources().getQuantityString(R.plurals.set_count, dBGroup.getNumSets(), Integer.valueOf(dBGroup.getNumSets())));
        long schoolId = dBGroup.getSchoolId();
        QTextView qTextView = (QTextView) nVarW2.e;
        if (schoolId == 0) {
            qTextView.setText((CharSequence) null);
            return;
        }
        if (dBGroup.getSchool() != null) {
            qTextView.setText(dBGroup.getSchool().getSchoolString());
            return;
        }
        timber.log.c.a.e(new RuntimeException("Group with schoolId( " + dBGroup + ".schoolId ) does not have school include"));
    }

    public final long U() {
        return ((Number) this.A.getValue()).longValue();
    }

    public final com.quizlet.data.repository.user.a V() {
        com.quizlet.data.repository.user.a aVar = this.y;
        if (aVar != null) {
            return aVar;
        }
        Intrinsics.m("groupDataProvider");
        throw null;
    }

    public final n W() {
        n nVar = this.L;
        if (nVar != null) {
            return nVar;
        }
        throw new IllegalArgumentException("Required value was null.");
    }

    public final void X() throws Resources.NotFoundException {
        ((QButton) W().g).setVisibility(8);
        ((QTabLayout) ((H) J()).b.d).setVisibility(0);
        ((H) J()).d.setSwipeable(true);
        AbstractC1136h0 childFragmentManager = getChildFragmentManager();
        Intrinsics.checkNotNullExpressionValue(childFragmentManager, "getChildFragmentManager(...)");
        ((H) J()).d.setAdapter(new d(this, childFragmentManager));
    }

    @Override // android.view.ActionMode.Callback
    public final boolean onActionItemClicked(ActionMode actionMode, MenuItem menuItem) {
        return false;
    }

    @Override // androidx.fragment.app.Fragment
    public final void onActivityResult(int i, int i2, Intent intent) {
        super.onActivityResult(i, i2, intent);
        if (i == 218 && i2 == -1) {
            String string = getString(R.string.add_set_classes_complete);
            Intrinsics.checkNotNullExpressionValue(string, "getString(...)");
            I6.d(((H) J()).d, string).i();
        }
    }

    @Override // com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        String[] args = {"KEY_GROUP_CLASS_ID"};
        Intrinsics.checkNotNullParameter(this, "<this>");
        Intrinsics.checkNotNullParameter(args, "args");
        String str = args[0];
        Bundle arguments = getArguments();
        if (arguments != null && !arguments.containsKey(str)) {
            throw new IllegalStateException(android.support.v4.media.session.a.B("Fragment launched without required argument key:(", str, ")"));
        }
        setHasOptionsMenu(true);
    }

    @Override // android.view.ActionMode.Callback
    public final boolean onCreateActionMode(ActionMode actionMode, Menu menu) {
        ((H) J()).d.setVisibility(8);
        ((H) J()).d.setSwipeable(false);
        return true;
    }

    @Override // com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final View onCreateView(LayoutInflater inflater, ViewGroup viewGroup, Bundle bundle) {
        Intrinsics.checkNotNullParameter(inflater, "inflater");
        View viewOnCreateView = super.onCreateView(inflater, viewGroup, bundle);
        View viewInflate = getLayoutInflater().inflate(R.layout.activity_class_header, (ViewGroup) null, false);
        int i = R.id.auto_join_button;
        QButton qButton = (QButton) AbstractC3375o2.c(R.id.auto_join_button, viewInflate);
        if (qButton != null) {
            i = R.id.class_detail_group;
            LinearLayout linearLayout = (LinearLayout) AbstractC3375o2.c(R.id.class_detail_group, viewInflate);
            if (linearLayout != null) {
                i = R.id.class_header_groupname;
                QTextView qTextView = (QTextView) AbstractC3375o2.c(R.id.class_header_groupname, viewInflate);
                if (qTextView != null) {
                    i = R.id.class_header_schoolname;
                    QTextView qTextView2 = (QTextView) AbstractC3375o2.c(R.id.class_header_schoolname, viewInflate);
                    if (qTextView2 != null) {
                        i = R.id.class_set_count_label;
                        QTextView qTextView3 = (QTextView) AbstractC3375o2.c(R.id.class_set_count_label, viewInflate);
                        if (qTextView3 != null) {
                            this.L = new n((LinearLayout) viewInflate, qButton, linearLayout, qTextView, qTextView2, qTextView3);
                            com.quizlet.data.repository.user.a aVarV = V();
                            long jU = U();
                            com.quizlet.infra.legacysyncengine.managers.d dVar = this.r;
                            if (dVar == null) {
                                Intrinsics.m("loggedInUserManager");
                                throw null;
                            }
                            long personId = dVar.e.getPersonId();
                            com.quizlet.infra.legacysyncengine.net.c loader = (com.quizlet.infra.legacysyncengine.net.c) ((com.quizlet.data.interactor.course.a) aVarV.b).b;
                            Intrinsics.checkNotNullParameter(loader, "loader");
                            com.quizlet.infra.legacysyncengine.orm.b bVar = new com.quizlet.infra.legacysyncengine.orm.b(Models.GROUP);
                            bVar.b(Long.valueOf(jU), DBGroupFields.ID);
                            bVar.e(DBGroupFields.SCHOOL);
                            bVar.e(DBGroupFields.CREATOR);
                            aVarV.c = new com.quizlet.features.infra.studysetting.datasource.a(loader, bVar.a());
                            Long lValueOf = Long.valueOf(jU);
                            Intrinsics.checkNotNullParameter(loader, "loader");
                            ModelType<DBGroupMembership> modelType = Models.GROUP_MEMBERSHIP;
                            com.quizlet.infra.legacysyncengine.orm.b bVar2 = new com.quizlet.infra.legacysyncengine.orm.b(modelType);
                            Relationship<DBGroupMembership, DBUser> relationship = DBGroupMembershipFields.USER;
                            bVar2.b(Long.valueOf(personId), relationship);
                            bVar2.b(lValueOf, DBGroupMembershipFields.CLASS);
                            aVarV.d = new com.quizlet.features.infra.studysetting.datasource.a(loader, bVar2.a());
                            com.quizlet.shared.usecase.srs.a aVar = this.t;
                            if (aVar == null) {
                                Intrinsics.m("addSetToClassFeature");
                                throw null;
                            }
                            androidx.work.impl.model.c cVar = this.l;
                            if (cVar == null) {
                                Intrinsics.m("userProperties");
                                throw null;
                            }
                            u uVar = this.D;
                            io.reactivex.rxjava3.internal.operators.single.g s1 = aVar.v(cVar, (com.quizlet.quizletandroid.config.features.properties.b) uVar.getValue());
                            com.google.android.material.floatingactionbutton.c cVar2 = this.u;
                            if (cVar2 == null) {
                                Intrinsics.m("addFolderToClassFeature");
                                throw null;
                            }
                            androidx.work.impl.model.c userProps = this.l;
                            if (userProps == null) {
                                Intrinsics.m("userProperties");
                                throw null;
                            }
                            com.quizlet.quizletandroid.config.features.properties.b contentProps = (com.quizlet.quizletandroid.config.features.properties.b) uVar.getValue();
                            cVar2.getClass();
                            Intrinsics.checkNotNullParameter(userProps, "userProps");
                            Intrinsics.checkNotNullParameter(contentProps, "contentProps");
                            io.reactivex.rxjava3.internal.operators.single.g gVarV = ((com.quizlet.shared.usecase.srs.a) cVar2.b).v(userProps, contentProps);
                            io.reactivex.rxjava3.internal.operators.single.g userId = userProps.n();
                            contentProps.getClass();
                            Intrinsics.checkNotNullParameter(userId, "userId");
                            p pVarP = p.p(contentProps.a, userId, com.quizlet.quizletandroid.config.features.properties.a.d);
                            Intrinsics.checkNotNullExpressionValue(pVarP, "zip(...)");
                            io.reactivex.rxjava3.internal.operators.single.g s2 = com.google.android.gms.dynamite.d.b(gVarV, pVarP);
                            com.quizlet.shared.usecase.srs.a aVar2 = this.v;
                            if (aVar2 == null) {
                                Intrinsics.m("canInviteMembersToClassFeature");
                                throw null;
                            }
                            androidx.work.impl.model.c cVar3 = this.l;
                            if (cVar3 == null) {
                                Intrinsics.m("userProperties");
                                throw null;
                            }
                            io.reactivex.rxjava3.internal.operators.single.g s3 = aVar2.v(cVar3, (com.quizlet.quizletandroid.config.features.properties.b) uVar.getValue());
                            Intrinsics.checkNotNullParameter(s1, "s1");
                            Intrinsics.checkNotNullParameter(s2, "s2");
                            Intrinsics.checkNotNullParameter(s3, "s3");
                            p pVarO = p.o(s1, s2, s3, io.reactivex.rxjava3.kotlin.a.e);
                            Intrinsics.checkNotNullExpressionValue(pVarO, "Single.zip(s1, s2, s3, F… -> Triple(t1, t2, t3) })");
                            g gVar = new g(this, 6);
                            com.quizlet.infra.legacysyncengine.net.request.g gVar2 = io.reactivex.rxjava3.internal.functions.d.e;
                            io.reactivex.rxjava3.internal.observers.e eVarI = pVarO.i(gVar, gVar2);
                            Intrinsics.checkNotNullExpressionValue(eVarI, "subscribe(...)");
                            I(eVarI);
                            if (!((Boolean) this.C.getValue()).booleanValue()) {
                                return viewOnCreateView;
                            }
                            com.quizlet.infra.legacysyncengine.orm.b bVar3 = new com.quizlet.infra.legacysyncengine.orm.b(modelType);
                            com.quizlet.infra.legacysyncengine.managers.d dVar2 = this.r;
                            if (dVar2 == null) {
                                Intrinsics.m("loggedInUserManager");
                                throw null;
                            }
                            bVar3.b(Long.valueOf(dVar2.e.getPersonId()), relationship);
                            com.quizlet.infra.legacysyncengine.orm.query.a aVarA = bVar3.a();
                            com.quizlet.infra.legacysyncengine.net.c cVar4 = this.j;
                            if (cVar4 == null) {
                                Intrinsics.m("loader");
                                throw null;
                            }
                            io.reactivex.rxjava3.internal.operators.flowable.b bVarB = cVar4.b(aVarA, com.quizlet.infra.legacysyncengine.net.b.b);
                            com.quizlet.infra.legacysyncengine.net.c cVar5 = this.j;
                            if (cVar5 == null) {
                                Intrinsics.m("loader");
                                throw null;
                            }
                            io.reactivex.rxjava3.internal.operators.single.g gVarG = p.p(bVarB, cVar5.b(aVarA, com.quizlet.infra.legacysyncengine.net.b.a), f.a).g(new com.quizlet.quizletandroid.k(this, 5));
                            o oVar = this.q;
                            if (oVar == null) {
                                Intrinsics.m("requestScheduler");
                                throw null;
                            }
                            io.reactivex.rxjava3.internal.operators.single.k kVarL = gVarG.l(oVar);
                            Intrinsics.checkNotNullExpressionValue(kVarL, "subscribeOn(...)");
                            o oVar2 = this.p;
                            if (oVar2 == null) {
                                Intrinsics.m("mainThreadScheduler");
                                throw null;
                            }
                            io.reactivex.rxjava3.internal.observers.e eVarI2 = kVarL.h(oVar2).i(new g(this, 5), gVar2);
                            Intrinsics.checkNotNullExpressionValue(eVarI2, "subscribe(...)");
                            H(eVarI2);
                            return viewOnCreateView;
                        }
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(viewInflate.getResources().getResourceName(i)));
    }

    @Override // android.view.ActionMode.Callback
    public final void onDestroyActionMode(ActionMode actionMode) {
        ((H) J()).d.setVisibility(0);
        ((H) J()).d.setSwipeable(true);
    }

    @Override // com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final void onDestroyView() {
        super.onDestroyView();
        this.L = null;
    }

    @Override // androidx.fragment.app.Fragment
    public final boolean onOptionsItemSelected(MenuItem item) throws Exception {
        Intrinsics.checkNotNullParameter(item, "item");
        int itemId = item.getItemId();
        if (itemId == R.id.add_sets) {
            long jU = U();
            com.quizlet.data.interactor.achievements.f fVar = this.w;
            if (fVar == null) {
                Intrinsics.m("addToClassPermissionHelper");
                throw null;
            }
            if (!fVar.p()) {
                com.quizlet.uicommon.ui.common.dialogs.l.P(R.string.add_class_under_13_title_dialog, R.string.add_class_under_13_msg_dialog, R.string.got_it).O(getChildFragmentManager(), "l");
                return true;
            }
            com.quizlet.features.notes.a aVar = this.x;
            if (aVar == null) {
                Intrinsics.m("classContentLogger");
                throw null;
            }
            EventLoggerExt.c(aVar.a, new m(25, jU));
            Context contextRequireContext = requireContext();
            Long lValueOf = Long.valueOf(jU);
            int i = AddClassSetActivity.w;
            Intent intent = new Intent(contextRequireContext, (Class<?>) AddClassSetActivity.class);
            intent.putExtra("current_class_id", lValueOf);
            startActivityForResult(intent, 218);
            return true;
        }
        if (itemId == R.id.add_folders) {
            com.quizlet.features.notes.a aVar2 = this.x;
            if (aVar2 == null) {
                Intrinsics.m("classContentLogger");
                throw null;
            }
            EventLoggerExt.c(aVar2.a, new m(24, U()));
            String str = JoinContentToFolderActivity.r;
            Context context = requireContext();
            Intrinsics.checkNotNullExpressionValue(context, "requireContext(...)");
            long jU2 = U();
            Intrinsics.checkNotNullParameter(context, "context");
            Intent intent2 = new Intent(context, (Class<?>) JoinContentToFolderActivity.class);
            intent2.putExtra(DBGroupMembershipFields.Names.CLASS_ID, jU2);
            startActivityForResult(intent2, 229);
            return true;
        }
        if (itemId == R.id.invite_members) {
            String string = ((QTextView) W().d).getText().toString();
            String str2 = this.G;
            String string2 = getResources().getString(R.string.join_link_title, string);
            Intrinsics.checkNotNullExpressionValue(string2, "getString(...)");
            String string3 = getResources().getString(R.string.join_link_message, string, str2);
            Intrinsics.checkNotNullExpressionValue(string3, "getString(...)");
            U u = new U(requireActivity());
            Intent intent3 = u.a;
            intent3.setType("text/plain");
            intent3.putExtra("android.intent.extra.SUBJECT", string2);
            intent3.putExtra("android.intent.extra.TEXT", (CharSequence) string3);
            Intent intentA = u.a();
            if (intentA.resolveActivity(requireActivity().getPackageManager()) != null) {
                startActivity(intentA);
            }
            return true;
        }
        if (itemId == R.id.report) {
            if (this.z == null) {
                Intrinsics.m("reportContent");
                throw null;
            }
            I iRequireActivity = requireActivity();
            Intrinsics.checkNotNullExpressionValue(iRequireActivity, "requireActivity(...)");
            com.quizlet.quizletandroid.ui.common.adapter.c.h(4, U(), iRequireActivity);
            return true;
        }
        if (itemId != R.id.menu_drop_class) {
            return super.onOptionsItemSelected(item);
        }
        e.a aVar3 = new e.a(requireContext());
        aVar3.c(R.string.confirm_drop_class);
        String string4 = getString(R.string.yes_dialog_button);
        com.quizlet.infra.legacysyncengine.tasks.parse.b bVar = new com.quizlet.infra.legacysyncengine.tasks.parse.b(this, 5);
        aVar3.i = string4;
        aVar3.j = bVar;
        aVar3.d(R.string.cancel_dialog_button, null);
        aVar3.g();
        return true;
    }

    @Override // android.view.ActionMode.Callback
    public final boolean onPrepareActionMode(ActionMode actionMode, Menu menu) {
        return false;
    }

    @Override // androidx.fragment.app.Fragment
    public final void onPrepareOptionsMenu(Menu menu) {
        Intrinsics.checkNotNullParameter(menu, "menu");
        super.onPrepareOptionsMenu(menu);
        androidx.work.impl.model.f.b(menu, R.id.add_sets, this.I);
        androidx.work.impl.model.f.b(menu, R.id.add_folders, this.J);
        androidx.work.impl.model.f.b(menu, R.id.invite_members, this.K);
        DBGroupMembership dBGroupMembership = this.H;
        androidx.work.impl.model.f.b(menu, R.id.menu_drop_class, (dBGroupMembership != null ? dBGroupMembership.getLevel() : -4) >= 1);
    }

    @Override // androidx.fragment.app.Fragment
    public final void onSaveInstanceState(Bundle outState) {
        Intrinsics.checkNotNullParameter(outState, "outState");
        outState.putLong("KEY_GROUP_CLASS_ID", U());
    }

    @Override // com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final void onStart() {
        com.quizlet.features.infra.studysetting.datasource.a aVar = (com.quizlet.features.infra.studysetting.datasource.a) V().c;
        if (aVar == null) {
            Intrinsics.m("groupDataSource");
            throw null;
        }
        J jQ = aVar.f().l(com.quizlet.quizletandroid.ui.group.data.a.d).q(com.quizlet.quizletandroid.ui.group.data.a.e);
        Intrinsics.checkNotNullExpressionValue(jQ, "map(...)");
        o oVar = this.p;
        if (oVar == null) {
            Intrinsics.m("mainThreadScheduler");
            throw null;
        }
        W wS = jQ.s(oVar);
        g gVar = new g(this, 3);
        com.quizlet.infra.legacysyncengine.net.request.g gVar2 = io.reactivex.rxjava3.internal.functions.d.e;
        io.reactivex.rxjava3.internal.functions.b bVar = io.reactivex.rxjava3.internal.functions.d.c;
        io.reactivex.rxjava3.disposables.b bVarU = wS.u(gVar, gVar2, bVar);
        Intrinsics.checkNotNullExpressionValue(bVarU, "subscribe(...)");
        I(bVarU);
        com.quizlet.features.infra.studysetting.datasource.a aVar2 = (com.quizlet.features.infra.studysetting.datasource.a) V().d;
        if (aVar2 == null) {
            Intrinsics.m("groupMembershipDataSource");
            throw null;
        }
        J jQ2 = aVar2.f().l(com.quizlet.quizletandroid.ui.group.data.a.b).q(com.quizlet.quizletandroid.ui.group.data.a.c);
        Intrinsics.checkNotNullExpressionValue(jQ2, "map(...)");
        o oVar2 = this.p;
        if (oVar2 == null) {
            Intrinsics.m("mainThreadScheduler");
            throw null;
        }
        io.reactivex.rxjava3.disposables.b bVarU2 = jQ2.s(oVar2).u(new g(this, 4), gVar2, bVar);
        Intrinsics.checkNotNullExpressionValue(bVarU2, "subscribe(...)");
        I(bVarU2);
        super.onStart();
    }

    @Override // com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final void onStop() {
        super.onStop();
        com.quizlet.data.repository.user.a aVarV = V();
        com.quizlet.features.infra.studysetting.datasource.a aVar = (com.quizlet.features.infra.studysetting.datasource.a) aVarV.c;
        if (aVar == null) {
            Intrinsics.m("groupDataSource");
            throw null;
        }
        aVar.g();
        com.quizlet.features.infra.studysetting.datasource.a aVar2 = (com.quizlet.features.infra.studysetting.datasource.a) aVarV.d;
        if (aVar2 != null) {
            aVar2.g();
        } else {
            Intrinsics.m("groupMembershipDataSource");
            throw null;
        }
    }

    @Override // com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final void onViewCreated(View view, Bundle bundle) throws Resources.NotFoundException {
        Intrinsics.checkNotNullParameter(view, "view");
        super.onViewCreated(view, bundle);
        H h = (H) J();
        com.quizlet.infra.legacysyncengine.models.serializers.a aVar = new com.quizlet.infra.legacysyncengine.models.serializers.a(19);
        WeakHashMap weakHashMap = V.a;
        L.m(h.a, aVar);
        I activity = getActivity();
        AbstractActivityC0055k abstractActivityC0055k = activity instanceof AbstractActivityC0055k ? (AbstractActivityC0055k) activity : null;
        if (abstractActivityC0055k != null) {
            abstractActivityC0055k.v((Toolbar) ((H) J()).b.e);
            com.bumptech.glide.c cVarR = abstractActivityC0055k.r();
            if (cVarR != null) {
                cVarR.s(true);
            }
        }
        com.quizlet.features.infra.legacyadapter.databinding.f fVar = ((H) J()).b;
        ((QTabLayout) fVar.d).setupWithViewPager(((H) J()).d);
        AbstractC1136h0 childFragmentManager = getChildFragmentManager();
        Intrinsics.checkNotNullExpressionValue(childFragmentManager, "getChildFragmentManager(...)");
        ((H) J()).d.setAdapter(new d(this, childFragmentManager));
        FrameLayout frameLayout = (FrameLayout) fVar.c;
        frameLayout.setVisibility(0);
        frameLayout.addView((LinearLayout) W().c);
        T(null);
        if (bundle == null) {
            EventLogger eventLogger = this.k;
            if (eventLogger != null) {
                eventLogger.J(4, U());
            } else {
                Intrinsics.m("eventLogger");
                throw null;
            }
        }
    }

    @Override // com.quizlet.baseui.interfaces.a
    public final void r() {
        com.quizlet.data.repository.user.a aVarV = V();
        com.quizlet.features.infra.studysetting.datasource.a aVar = (com.quizlet.features.infra.studysetting.datasource.a) aVarV.c;
        if (aVar == null) {
            Intrinsics.m("groupDataSource");
            throw null;
        }
        aVar.d();
        com.quizlet.features.infra.studysetting.datasource.a aVar2 = (com.quizlet.features.infra.studysetting.datasource.a) aVarV.d;
        if (aVar2 != null) {
            aVar2.d();
        } else {
            Intrinsics.m("groupMembershipDataSource");
            throw null;
        }
    }
}

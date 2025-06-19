package com.quizlet.quizletandroid.ui.profile;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.content.res.Resources;
import android.database.DataSetObserver;
import android.os.Bundle;
import android.view.ActionMode;
import android.view.LayoutInflater;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.TextView;
import androidx.appcompat.app.AbstractActivityC0055k;
import androidx.appcompat.widget.Toolbar;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.constraintlayout.widget.Group;
import androidx.coordinatorlayout.widget.CoordinatorLayout;
import androidx.core.view.L;
import androidx.core.view.V;
import androidx.fragment.app.AbstractC1136h0;
import androidx.fragment.app.I;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3242q6;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.google.android.gms.internal.mlkit_vision_common.C2;
import com.google.android.material.appbar.AppBarLayout;
import com.google.android.material.appbar.CollapsingToolbarLayout;
import com.quizlet.db.data.models.persisted.DBStudySet;
import com.quizlet.db.data.models.persisted.DBUser;
import com.quizlet.db.data.models.persisted.base.Models;
import com.quizlet.db.data.models.persisted.fields.DBStudySetFields;
import com.quizlet.db.data.orm.Relationship;
import com.quizlet.eventlogger.EventLogger;
import com.quizlet.features.achievements.achievement.AchievementEarnedView;
import com.quizlet.features.settings.SettingsActivity;
import com.quizlet.partskit.widgets.QTabLayout;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.databinding.D;
import com.quizlet.quizletandroid.ui.base.DataSourceRecyclerViewFragment;
import com.quizlet.quizletandroid.ui.common.views.ToggleSwipeableViewPager;
import com.quizlet.quizletandroid.ui.usersettings.activities.ChangeProfileImageActivity;
import com.quizlet.upgrade.ui.activity.UpgradeActivity;
import java.util.ArrayList;
import java.util.List;
import java.util.WeakHashMap;
import kotlin.Metadata;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.collections.B;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.K;
import kotlin.text.StringsKt;

@Metadata
/* loaded from: classes3.dex */
public final class ProfileFragment extends Hilt_ProfileFragment<D> implements com.quizlet.quizletandroid.ui.base.a, v, t, ActionMode.Callback, com.quizlet.baseui.interfaces.a {
    public static final String x;
    public static final int y;
    public com.quizlet.infra.legacysyncengine.datasources.o j;
    public androidx.activity.result.b k;
    public com.quizlet.infra.legacysyncengine.net.c l;
    public EventLogger m;
    public com.quizlet.qutils.image.loading.a n;
    public com.quizlet.quizletandroid.ui.common.adapter.c o;
    public final com.quizlet.data.repository.folderwithcreatorinclass.e p = new com.quizlet.data.repository.folderwithcreatorinclass.e(K.a(com.quizlet.quizletandroid.ui.profile.data.h.class), new g(this, 0), new g(this, 2), new g(this, 1));
    public final com.quizlet.data.repository.folderwithcreatorinclass.e q = new com.quizlet.data.repository.folderwithcreatorinclass.e(K.a(com.quizlet.features.achievements.notification.f.class), new g(this, 3), new g(this, 5), new g(this, 4));
    public com.quizlet.quizletandroid.ui.group.addclassset.a r;
    public boolean s;
    public final kotlin.u t;
    public final kotlin.u u;
    public final kotlin.u v;
    public Integer w;

    static {
        Intrinsics.checkNotNullExpressionValue("ProfileFragment", "getSimpleName(...)");
        x = "ProfileFragment";
        y = R.menu.profile_menu;
    }

    public ProfileFragment() {
        final int i = 0;
        this.t = kotlin.l.b(new Function0(this) { // from class: com.quizlet.quizletandroid.ui.profile.f
            public final /* synthetic */ ProfileFragment b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function0
            public final Object invoke() {
                ProfileFragment profileFragment = this.b;
                switch (i) {
                    case 0:
                        String str = ProfileFragment.x;
                        return Long.valueOf(profileFragment.requireArguments().getLong("userId", 0L));
                    case 1:
                        String str2 = ProfileFragment.x;
                        return Boolean.valueOf(profileFragment.requireArguments().getBoolean("fromActivityParent"));
                    default:
                        String str3 = ProfileFragment.x;
                        return profileFragment.requireArguments().getString("badgeId");
                }
            }
        });
        final int i2 = 1;
        this.u = kotlin.l.b(new Function0(this) { // from class: com.quizlet.quizletandroid.ui.profile.f
            public final /* synthetic */ ProfileFragment b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function0
            public final Object invoke() {
                ProfileFragment profileFragment = this.b;
                switch (i2) {
                    case 0:
                        String str = ProfileFragment.x;
                        return Long.valueOf(profileFragment.requireArguments().getLong("userId", 0L));
                    case 1:
                        String str2 = ProfileFragment.x;
                        return Boolean.valueOf(profileFragment.requireArguments().getBoolean("fromActivityParent"));
                    default:
                        String str3 = ProfileFragment.x;
                        return profileFragment.requireArguments().getString("badgeId");
                }
            }
        });
        final int i3 = 2;
        this.v = kotlin.l.b(new Function0(this) { // from class: com.quizlet.quizletandroid.ui.profile.f
            public final /* synthetic */ ProfileFragment b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function0
            public final Object invoke() {
                ProfileFragment profileFragment = this.b;
                switch (i3) {
                    case 0:
                        String str = ProfileFragment.x;
                        return Long.valueOf(profileFragment.requireArguments().getLong("userId", 0L));
                    case 1:
                        String str2 = ProfileFragment.x;
                        return Boolean.valueOf(profileFragment.requireArguments().getBoolean("fromActivityParent"));
                    default:
                        String str3 = ProfileFragment.x;
                        return profileFragment.requireArguments().getString("badgeId");
                }
            }
        });
    }

    @Override // com.quizlet.baseui.base.BaseFragment
    public final String K() {
        String string = getString(R.string.loggingTag_Profile);
        Intrinsics.checkNotNullExpressionValue(string, "getString(...)");
        return string;
    }

    @Override // com.quizlet.baseui.base.BaseFragment
    public final Integer M() {
        return Integer.valueOf(y);
    }

    @Override // com.quizlet.baseui.base.BaseFragment
    public final String N() {
        return x;
    }

    @Override // com.quizlet.baseui.base.BaseFragment
    public final androidx.viewbinding.a O(LayoutInflater inflater, ViewGroup viewGroup) {
        Intrinsics.checkNotNullParameter(inflater, "inflater");
        View viewInflate = inflater.inflate(R.layout.fragment_profile, viewGroup, false);
        int i = R.id.achievementToast;
        AchievementEarnedView achievementEarnedView = (AchievementEarnedView) AbstractC3375o2.c(R.id.achievementToast, viewInflate);
        if (achievementEarnedView != null) {
            i = R.id.buttonsGroup;
            Group group = (Group) AbstractC3375o2.c(R.id.buttonsGroup, viewInflate);
            if (group != null) {
                i = R.id.header;
                ConstraintLayout constraintLayout = (ConstraintLayout) AbstractC3375o2.c(R.id.header, viewInflate);
                if (constraintLayout != null) {
                    i = R.id.layout_collapsing_appbar;
                    if (((AppBarLayout) AbstractC3375o2.c(R.id.layout_collapsing_appbar, viewInflate)) != null) {
                        i = R.id.layout_collapsing_appbar_toolbar;
                        if (((CollapsingToolbarLayout) AbstractC3375o2.c(R.id.layout_collapsing_appbar_toolbar, viewInflate)) != null) {
                            i = R.id.profileViewPager;
                            ToggleSwipeableViewPager toggleSwipeableViewPager = (ToggleSwipeableViewPager) AbstractC3375o2.c(R.id.profileViewPager, viewInflate);
                            if (toggleSwipeableViewPager != null) {
                                i = R.id.settingButton;
                                ImageView imageView = (ImageView) AbstractC3375o2.c(R.id.settingButton, viewInflate);
                                if (imageView != null) {
                                    i = R.id.tabLayout;
                                    QTabLayout qTabLayout = (QTabLayout) AbstractC3375o2.c(R.id.tabLayout, viewInflate);
                                    if (qTabLayout != null) {
                                        i = R.id.toolbar;
                                        Toolbar toolbar = (Toolbar) AbstractC3375o2.c(R.id.toolbar, viewInflate);
                                        if (toolbar != null) {
                                            i = R.id.upgradeButton;
                                            TextView textView = (TextView) AbstractC3375o2.c(R.id.upgradeButton, viewInflate);
                                            if (textView != null) {
                                                i = R.id.userProfileAvatar;
                                                ImageView imageView2 = (ImageView) AbstractC3375o2.c(R.id.userProfileAvatar, viewInflate);
                                                if (imageView2 != null) {
                                                    i = R.id.userProfileUsername;
                                                    TextView textView2 = (TextView) AbstractC3375o2.c(R.id.userProfileUsername, viewInflate);
                                                    if (textView2 != null) {
                                                        D d = new D((CoordinatorLayout) viewInflate, achievementEarnedView, group, constraintLayout, toggleSwipeableViewPager, imageView, qTabLayout, toolbar, textView, imageView2, textView2);
                                                        Intrinsics.checkNotNullExpressionValue(d, "inflate(...)");
                                                        return d;
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(viewInflate.getResources().getResourceName(i)));
    }

    @Override // com.quizlet.baseui.base.BaseFragment
    public final boolean P() {
        return true;
    }

    public final void T(List newContent, Integer num) throws Resources.NotFoundException {
        if (((D) J()).e.getAdapter() == null) {
            AbstractC1136h0 childFragmentManager = getChildFragmentManager();
            Intrinsics.checkNotNullExpressionValue(childFragmentManager, "getChildFragmentManager(...)");
            this.r = new com.quizlet.quizletandroid.ui.group.addclassset.a(this, childFragmentManager, CollectionsKt.y0(newContent));
            ((D) J()).e.setAdapter(this.r);
        } else {
            com.quizlet.quizletandroid.ui.group.addclassset.a aVar = this.r;
            if (aVar != null) {
                Intrinsics.checkNotNullParameter(newContent, "newContent");
                ArrayList arrayList = (ArrayList) aVar.k;
                if (arrayList.size() != newContent.size()) {
                    arrayList.clear();
                    arrayList.addAll(newContent);
                    synchronized (aVar) {
                        try {
                            DataSetObserver dataSetObserver = aVar.b;
                            if (dataSetObserver != null) {
                                dataSetObserver.onChanged();
                            }
                        } catch (Throwable th) {
                            throw th;
                        }
                    }
                    aVar.a.notifyChanged();
                }
            }
        }
        D d = (D) J();
        com.quizlet.quizletandroid.ui.group.addclassset.a aVar2 = this.r;
        int iIndexOf = 0;
        d.e.setOffscreenPageLimit(aVar2 != null ? ((ArrayList) aVar2.k).size() : 0);
        if (num != null) {
            ((D) J()).e.setCurrentItem(num.intValue());
            return;
        }
        Bundle arguments = getArguments();
        Integer numValueOf = arguments != null ? Integer.valueOf(arguments.getInt("jumpToTab", -1)) : null;
        if (numValueOf != null && numValueOf.intValue() == 0) {
            D d2 = (D) J();
            com.quizlet.quizletandroid.ui.group.addclassset.a aVar3 = this.r;
            if (aVar3 != null) {
                q item = q.f;
                Intrinsics.checkNotNullParameter(item, "item");
                iIndexOf = ((ArrayList) aVar3.k).indexOf(item);
            }
            d2.e.setCurrentItem(iIndexOf);
            return;
        }
        if (numValueOf != null && numValueOf.intValue() == 1) {
            D d3 = (D) J();
            com.quizlet.quizletandroid.ui.group.addclassset.a aVar4 = this.r;
            if (aVar4 != null) {
                q item2 = q.e;
                Intrinsics.checkNotNullParameter(item2, "item");
                iIndexOf = ((ArrayList) aVar4.k).indexOf(item2);
            }
            d3.e.setCurrentItem(iIndexOf);
            return;
        }
        if (numValueOf != null && numValueOf.intValue() == 2) {
            D d4 = (D) J();
            com.quizlet.quizletandroid.ui.group.addclassset.a aVar5 = this.r;
            if (aVar5 != null) {
                q item3 = q.c;
                Intrinsics.checkNotNullParameter(item3, "item");
                iIndexOf = ((ArrayList) aVar5.k).indexOf(item3);
            }
            d4.e.setCurrentItem(iIndexOf);
            return;
        }
        if (numValueOf != null && numValueOf.intValue() == 3) {
            D d5 = (D) J();
            com.quizlet.quizletandroid.ui.group.addclassset.a aVar6 = this.r;
            if (aVar6 != null) {
                q item4 = q.d;
                Intrinsics.checkNotNullParameter(item4, "item");
                iIndexOf = ((ArrayList) aVar6.k).indexOf(item4);
            }
            d5.e.setCurrentItem(iIndexOf);
        }
    }

    public final void U(String str, String str2, boolean z) {
        D d = (D) J();
        d.k.setText(str);
        ImageView userProfileAvatar = d.j;
        Intrinsics.checkNotNullExpressionValue(userProfileAvatar, "userProfileAvatar");
        if (str2 == null || !(!StringsKt.O(str2))) {
            userProfileAvatar.setImageDrawable(null);
        } else {
            com.quizlet.qutils.image.loading.a aVar = this.n;
            if (aVar == null) {
                Intrinsics.m("imageLoader");
                throw null;
            }
            com.quizlet.data.repository.widget.b bVarP = ((com.quizlet.quizletandroid.ui.common.images.loading.glide.a) aVar).a(userProfileAvatar.getContext()).p(str2);
            bVarP.d();
            bVarP.o(userProfileAvatar);
        }
        Intrinsics.checkNotNullExpressionValue(userProfileAvatar, "userProfileAvatar");
        if (z) {
            userProfileAvatar.setOnClickListener(new e(this, 2));
        } else {
            userProfileAvatar.setOnClickListener(null);
        }
    }

    public final com.quizlet.infra.legacysyncengine.datasources.c V(DataSourceRecyclerViewFragment dataSourceRecyclerViewFragment) {
        if (!(dataSourceRecyclerViewFragment instanceof UserSetListFragment)) {
            throw new IllegalArgumentException("Unrecognized fragment: " + dataSourceRecyclerViewFragment);
        }
        com.quizlet.infra.legacysyncengine.datasources.o oVar = this.j;
        if (oVar != null) {
            return oVar;
        }
        Intrinsics.m("setDataSource");
        throw null;
    }

    public final long W() {
        return ((Number) this.t.getValue()).longValue();
    }

    public final com.quizlet.quizletandroid.ui.profile.data.h X() {
        return (com.quizlet.quizletandroid.ui.profile.data.h) this.p.getValue();
    }

    @Override // android.view.ActionMode.Callback
    public final boolean onActionItemClicked(ActionMode actionMode, MenuItem menuItem) {
        return false;
    }

    @Override // com.quizlet.quizletandroid.ui.profile.Hilt_ProfileFragment, androidx.fragment.app.Fragment
    public final void onAttach(Activity activity) {
        Intrinsics.checkNotNullParameter(activity, "activity");
        super.onAttach(activity);
        this.k = registerForActivityResult(new androidx.activity.result.contract.b(4), new com.quizlet.features.infra.photo.a(this));
    }

    @Override // com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        this.w = bundle != null ? Integer.valueOf(bundle.getInt("jumpToTab", -1)) : null;
        setHasOptionsMenu(true);
        if (W() == 0) {
            throw new IllegalStateException("User ID is 0, finishing activity");
        }
        com.quizlet.quizletandroid.ui.profile.data.h hVarX = X();
        long jW = W();
        hVarX.o = ((Boolean) this.u.getValue()).booleanValue();
        hVarX.n = jW;
        hVarX.h.a(x);
    }

    @Override // android.view.ActionMode.Callback
    public final boolean onCreateActionMode(ActionMode actionMode, Menu menu) {
        Intrinsics.checkNotNullParameter(actionMode, "actionMode");
        Intrinsics.checkNotNullParameter(menu, "menu");
        ((D) J()).e.setSwipeable(false);
        return true;
    }

    @Override // android.view.ActionMode.Callback
    public final void onDestroyActionMode(ActionMode actionMode) {
        Intrinsics.checkNotNullParameter(actionMode, "actionMode");
        ((D) J()).e.setSwipeable(true);
    }

    @Override // com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final void onDestroyView() {
        ((D) J()).b.setOnAchievementEventListener(null);
        super.onDestroyView();
    }

    @Override // androidx.fragment.app.Fragment
    public final boolean onOptionsItemSelected(MenuItem item) throws Resources.NotFoundException {
        Intrinsics.checkNotNullParameter(item, "item");
        if (item.getItemId() != R.id.report) {
            return super.onOptionsItemSelected(item);
        }
        if (this.o == null) {
            Intrinsics.m("reportContent");
            throw null;
        }
        I iRequireActivity = requireActivity();
        Intrinsics.checkNotNullExpressionValue(iRequireActivity, "requireActivity(...)");
        com.quizlet.quizletandroid.ui.common.adapter.c.h(2, W(), iRequireActivity);
        return true;
    }

    @Override // android.view.ActionMode.Callback
    public final boolean onPrepareActionMode(ActionMode actionMode, Menu menu) {
        Intrinsics.checkNotNullParameter(actionMode, "actionMode");
        Intrinsics.checkNotNullParameter(menu, "menu");
        return false;
    }

    @Override // androidx.fragment.app.Fragment
    public final void onPrepareOptionsMenu(Menu menu) {
        Intrinsics.checkNotNullParameter(menu, "menu");
        super.onPrepareOptionsMenu(menu);
        androidx.work.impl.model.f.b(menu, R.id.report, this.s);
    }

    @Override // androidx.fragment.app.Fragment
    public final void onSaveInstanceState(Bundle outState) {
        Intrinsics.checkNotNullParameter(outState, "outState");
        outState.putInt("jumpToTab", ((D) J()).e.getCurrentItem());
    }

    @Override // com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final void onViewCreated(View view, Bundle bundle) throws Resources.NotFoundException {
        final int i = 2;
        final int i2 = 0;
        final int i3 = 1;
        Intrinsics.checkNotNullParameter(view, "view");
        super.onViewCreated(view, bundle);
        D d = (D) J();
        com.quizlet.infra.legacysyncengine.tasks.parse.b bVar = new com.quizlet.infra.legacysyncengine.tasks.parse.b(this, 10);
        WeakHashMap weakHashMap = V.a;
        L.m(d.a, bVar);
        Intrinsics.checkNotNullParameter(this, "<this>");
        I activity = getActivity();
        Intrinsics.e(activity, "null cannot be cast to non-null type androidx.appcompat.app.AppCompatActivity");
        AbstractActivityC0055k abstractActivityC0055k = (AbstractActivityC0055k) activity;
        abstractActivityC0055k.v(((D) J()).h);
        com.bumptech.glide.c cVarR = abstractActivityC0055k.r();
        if (cVarR != null) {
            cVarR.s(true);
        }
        com.bumptech.glide.c cVarR2 = abstractActivityC0055k.r();
        if (cVarR2 != null) {
            cVarR2.t();
        }
        abstractActivityC0055k.setTitle(R.string.profile);
        D d2 = (D) J();
        d2.g.setupWithViewPager(((D) J()).e);
        D d3 = (D) J();
        d3.f.setOnClickListener(new e(this, i2));
        d3.i.setOnClickListener(new e(this, i3));
        final int i4 = 3;
        X().j.f(getViewLifecycleOwner(), new com.quizlet.explanations.feedback.ui.fragments.c(13, new Function1(this) { // from class: com.quizlet.quizletandroid.ui.profile.d
            public final /* synthetic */ ProfileFragment b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function1
            public final Object invoke(Object obj) throws Exception {
                ProfileFragment profileFragment = this.b;
                switch (i4) {
                    case 0:
                        String str = ProfileFragment.x;
                        Context contextRequireContext = profileFragment.requireContext();
                        Intrinsics.checkNotNullExpressionValue(contextRequireContext, "requireContext(...)");
                        ((com.quizlet.features.infra.snackbar.m) obj).a(contextRequireContext);
                        return Unit.a;
                    case 1:
                        com.quizlet.features.achievements.notification.c cVar = (com.quizlet.features.achievements.notification.c) obj;
                        String str2 = ProfileFragment.x;
                        if (cVar instanceof com.quizlet.features.achievements.notification.a) {
                            ((D) profileFragment.J()).b.g(((com.quizlet.features.achievements.notification.a) cVar).a);
                        }
                        return Unit.a;
                    case 2:
                        l lVar = (l) obj;
                        String str3 = ProfileFragment.x;
                        if (lVar instanceof j) {
                            int i5 = SettingsActivity.p;
                            Context contextRequireContext2 = profileFragment.requireContext();
                            Intrinsics.checkNotNullExpressionValue(contextRequireContext2, "requireContext(...)");
                            profileFragment.startActivity(C2.c(contextRequireContext2));
                        } else if (lVar instanceof k) {
                            ((k) lVar).getClass();
                            com.quizlet.features.infra.models.upgrade.a aVar = com.quizlet.features.infra.models.upgrade.a.r;
                            String str4 = UpgradeActivity.v;
                            Context contextRequireContext3 = profileFragment.requireContext();
                            Intrinsics.checkNotNullExpressionValue(contextRequireContext3, "requireContext(...)");
                            profileFragment.startActivityForResult(AbstractC3242q6.i(contextRequireContext3, "chiclet", aVar), 224);
                        } else {
                            if (!(lVar instanceof i)) {
                                throw new NoWhenBranchMatchedException();
                            }
                            i iVar = (i) lVar;
                            Context contextRequireContext4 = profileFragment.requireContext();
                            String str5 = iVar.a;
                            int i6 = ChangeProfileImageActivity.q;
                            Intent intent = new Intent(contextRequireContext4, (Class<?>) ChangeProfileImageActivity.class);
                            intent.putExtra("EXTRA_PROFILE_IMAGE_ID", str5);
                            intent.putExtra("EXTRA_ALLOW_CUSTOM_IMAGES", iVar.b);
                            androidx.activity.result.b bVar2 = profileFragment.k;
                            if (bVar2 == null) {
                                Intrinsics.m("changeProfileImageResultLauncher");
                                throw null;
                            }
                            bVar2.a(intent);
                        }
                        return Unit.a;
                    case 3:
                        com.quizlet.quizletandroid.ui.profile.data.i iVar2 = (com.quizlet.quizletandroid.ui.profile.data.i) obj;
                        String str6 = ProfileFragment.x;
                        Intrinsics.d(iVar2);
                        if (!iVar2.d) {
                            Intrinsics.checkNotNullParameter(profileFragment, "<this>");
                            I activity2 = profileFragment.getActivity();
                            Intrinsics.e(activity2, "null cannot be cast to non-null type androidx.appcompat.app.AppCompatActivity");
                            com.bumptech.glide.c cVarR3 = ((AbstractActivityC0055k) activity2).r();
                            if (cVarR3 != null) {
                                cVarR3.k();
                            }
                            ViewGroup.LayoutParams layoutParams = ((D) profileFragment.J()).d.getLayoutParams();
                            Intrinsics.e(layoutParams, "null cannot be cast to non-null type android.view.ViewGroup.MarginLayoutParams");
                            ((ViewGroup.MarginLayoutParams) layoutParams).topMargin = 0;
                        }
                        Group buttonsGroup = ((D) profileFragment.J()).c;
                        Intrinsics.checkNotNullExpressionValue(buttonsGroup, "buttonsGroup");
                        boolean z = iVar2.e;
                        buttonsGroup.setVisibility(z ? 0 : 8);
                        TextView upgradeButton = ((D) profileFragment.J()).i;
                        Intrinsics.checkNotNullExpressionValue(upgradeButton, "upgradeButton");
                        upgradeButton.setVisibility((z && iVar2.f) ? 0 : 8);
                        profileFragment.U(iVar2.a, iVar2.b, z);
                        profileFragment.s = iVar2.c;
                        profileFragment.requireActivity().invalidateOptionsMenu();
                        return Unit.a;
                    default:
                        List list = (List) obj;
                        String str7 = ProfileFragment.x;
                        Intrinsics.d(list);
                        profileFragment.T(list, profileFragment.w);
                        return Unit.a;
                }
            }
        }));
        final int i5 = 4;
        X().k.f(getViewLifecycleOwner(), new com.quizlet.explanations.feedback.ui.fragments.c(13, new Function1(this) { // from class: com.quizlet.quizletandroid.ui.profile.d
            public final /* synthetic */ ProfileFragment b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function1
            public final Object invoke(Object obj) throws Exception {
                ProfileFragment profileFragment = this.b;
                switch (i5) {
                    case 0:
                        String str = ProfileFragment.x;
                        Context contextRequireContext = profileFragment.requireContext();
                        Intrinsics.checkNotNullExpressionValue(contextRequireContext, "requireContext(...)");
                        ((com.quizlet.features.infra.snackbar.m) obj).a(contextRequireContext);
                        return Unit.a;
                    case 1:
                        com.quizlet.features.achievements.notification.c cVar = (com.quizlet.features.achievements.notification.c) obj;
                        String str2 = ProfileFragment.x;
                        if (cVar instanceof com.quizlet.features.achievements.notification.a) {
                            ((D) profileFragment.J()).b.g(((com.quizlet.features.achievements.notification.a) cVar).a);
                        }
                        return Unit.a;
                    case 2:
                        l lVar = (l) obj;
                        String str3 = ProfileFragment.x;
                        if (lVar instanceof j) {
                            int i52 = SettingsActivity.p;
                            Context contextRequireContext2 = profileFragment.requireContext();
                            Intrinsics.checkNotNullExpressionValue(contextRequireContext2, "requireContext(...)");
                            profileFragment.startActivity(C2.c(contextRequireContext2));
                        } else if (lVar instanceof k) {
                            ((k) lVar).getClass();
                            com.quizlet.features.infra.models.upgrade.a aVar = com.quizlet.features.infra.models.upgrade.a.r;
                            String str4 = UpgradeActivity.v;
                            Context contextRequireContext3 = profileFragment.requireContext();
                            Intrinsics.checkNotNullExpressionValue(contextRequireContext3, "requireContext(...)");
                            profileFragment.startActivityForResult(AbstractC3242q6.i(contextRequireContext3, "chiclet", aVar), 224);
                        } else {
                            if (!(lVar instanceof i)) {
                                throw new NoWhenBranchMatchedException();
                            }
                            i iVar = (i) lVar;
                            Context contextRequireContext4 = profileFragment.requireContext();
                            String str5 = iVar.a;
                            int i6 = ChangeProfileImageActivity.q;
                            Intent intent = new Intent(contextRequireContext4, (Class<?>) ChangeProfileImageActivity.class);
                            intent.putExtra("EXTRA_PROFILE_IMAGE_ID", str5);
                            intent.putExtra("EXTRA_ALLOW_CUSTOM_IMAGES", iVar.b);
                            androidx.activity.result.b bVar2 = profileFragment.k;
                            if (bVar2 == null) {
                                Intrinsics.m("changeProfileImageResultLauncher");
                                throw null;
                            }
                            bVar2.a(intent);
                        }
                        return Unit.a;
                    case 3:
                        com.quizlet.quizletandroid.ui.profile.data.i iVar2 = (com.quizlet.quizletandroid.ui.profile.data.i) obj;
                        String str6 = ProfileFragment.x;
                        Intrinsics.d(iVar2);
                        if (!iVar2.d) {
                            Intrinsics.checkNotNullParameter(profileFragment, "<this>");
                            I activity2 = profileFragment.getActivity();
                            Intrinsics.e(activity2, "null cannot be cast to non-null type androidx.appcompat.app.AppCompatActivity");
                            com.bumptech.glide.c cVarR3 = ((AbstractActivityC0055k) activity2).r();
                            if (cVarR3 != null) {
                                cVarR3.k();
                            }
                            ViewGroup.LayoutParams layoutParams = ((D) profileFragment.J()).d.getLayoutParams();
                            Intrinsics.e(layoutParams, "null cannot be cast to non-null type android.view.ViewGroup.MarginLayoutParams");
                            ((ViewGroup.MarginLayoutParams) layoutParams).topMargin = 0;
                        }
                        Group buttonsGroup = ((D) profileFragment.J()).c;
                        Intrinsics.checkNotNullExpressionValue(buttonsGroup, "buttonsGroup");
                        boolean z = iVar2.e;
                        buttonsGroup.setVisibility(z ? 0 : 8);
                        TextView upgradeButton = ((D) profileFragment.J()).i;
                        Intrinsics.checkNotNullExpressionValue(upgradeButton, "upgradeButton");
                        upgradeButton.setVisibility((z && iVar2.f) ? 0 : 8);
                        profileFragment.U(iVar2.a, iVar2.b, z);
                        profileFragment.s = iVar2.c;
                        profileFragment.requireActivity().invalidateOptionsMenu();
                        return Unit.a;
                    default:
                        List list = (List) obj;
                        String str7 = ProfileFragment.x;
                        Intrinsics.d(list);
                        profileFragment.T(list, profileFragment.w);
                        return Unit.a;
                }
            }
        }));
        X().m.f(getViewLifecycleOwner(), new com.quizlet.explanations.feedback.ui.fragments.c(13, new Function1(this) { // from class: com.quizlet.quizletandroid.ui.profile.d
            public final /* synthetic */ ProfileFragment b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function1
            public final Object invoke(Object obj) throws Exception {
                ProfileFragment profileFragment = this.b;
                switch (i2) {
                    case 0:
                        String str = ProfileFragment.x;
                        Context contextRequireContext = profileFragment.requireContext();
                        Intrinsics.checkNotNullExpressionValue(contextRequireContext, "requireContext(...)");
                        ((com.quizlet.features.infra.snackbar.m) obj).a(contextRequireContext);
                        return Unit.a;
                    case 1:
                        com.quizlet.features.achievements.notification.c cVar = (com.quizlet.features.achievements.notification.c) obj;
                        String str2 = ProfileFragment.x;
                        if (cVar instanceof com.quizlet.features.achievements.notification.a) {
                            ((D) profileFragment.J()).b.g(((com.quizlet.features.achievements.notification.a) cVar).a);
                        }
                        return Unit.a;
                    case 2:
                        l lVar = (l) obj;
                        String str3 = ProfileFragment.x;
                        if (lVar instanceof j) {
                            int i52 = SettingsActivity.p;
                            Context contextRequireContext2 = profileFragment.requireContext();
                            Intrinsics.checkNotNullExpressionValue(contextRequireContext2, "requireContext(...)");
                            profileFragment.startActivity(C2.c(contextRequireContext2));
                        } else if (lVar instanceof k) {
                            ((k) lVar).getClass();
                            com.quizlet.features.infra.models.upgrade.a aVar = com.quizlet.features.infra.models.upgrade.a.r;
                            String str4 = UpgradeActivity.v;
                            Context contextRequireContext3 = profileFragment.requireContext();
                            Intrinsics.checkNotNullExpressionValue(contextRequireContext3, "requireContext(...)");
                            profileFragment.startActivityForResult(AbstractC3242q6.i(contextRequireContext3, "chiclet", aVar), 224);
                        } else {
                            if (!(lVar instanceof i)) {
                                throw new NoWhenBranchMatchedException();
                            }
                            i iVar = (i) lVar;
                            Context contextRequireContext4 = profileFragment.requireContext();
                            String str5 = iVar.a;
                            int i6 = ChangeProfileImageActivity.q;
                            Intent intent = new Intent(contextRequireContext4, (Class<?>) ChangeProfileImageActivity.class);
                            intent.putExtra("EXTRA_PROFILE_IMAGE_ID", str5);
                            intent.putExtra("EXTRA_ALLOW_CUSTOM_IMAGES", iVar.b);
                            androidx.activity.result.b bVar2 = profileFragment.k;
                            if (bVar2 == null) {
                                Intrinsics.m("changeProfileImageResultLauncher");
                                throw null;
                            }
                            bVar2.a(intent);
                        }
                        return Unit.a;
                    case 3:
                        com.quizlet.quizletandroid.ui.profile.data.i iVar2 = (com.quizlet.quizletandroid.ui.profile.data.i) obj;
                        String str6 = ProfileFragment.x;
                        Intrinsics.d(iVar2);
                        if (!iVar2.d) {
                            Intrinsics.checkNotNullParameter(profileFragment, "<this>");
                            I activity2 = profileFragment.getActivity();
                            Intrinsics.e(activity2, "null cannot be cast to non-null type androidx.appcompat.app.AppCompatActivity");
                            com.bumptech.glide.c cVarR3 = ((AbstractActivityC0055k) activity2).r();
                            if (cVarR3 != null) {
                                cVarR3.k();
                            }
                            ViewGroup.LayoutParams layoutParams = ((D) profileFragment.J()).d.getLayoutParams();
                            Intrinsics.e(layoutParams, "null cannot be cast to non-null type android.view.ViewGroup.MarginLayoutParams");
                            ((ViewGroup.MarginLayoutParams) layoutParams).topMargin = 0;
                        }
                        Group buttonsGroup = ((D) profileFragment.J()).c;
                        Intrinsics.checkNotNullExpressionValue(buttonsGroup, "buttonsGroup");
                        boolean z = iVar2.e;
                        buttonsGroup.setVisibility(z ? 0 : 8);
                        TextView upgradeButton = ((D) profileFragment.J()).i;
                        Intrinsics.checkNotNullExpressionValue(upgradeButton, "upgradeButton");
                        upgradeButton.setVisibility((z && iVar2.f) ? 0 : 8);
                        profileFragment.U(iVar2.a, iVar2.b, z);
                        profileFragment.s = iVar2.c;
                        profileFragment.requireActivity().invalidateOptionsMenu();
                        return Unit.a;
                    default:
                        List list = (List) obj;
                        String str7 = ProfileFragment.x;
                        Intrinsics.d(list);
                        profileFragment.T(list, profileFragment.w);
                        return Unit.a;
                }
            }
        }));
        com.quizlet.data.repository.folderwithcreatorinclass.e eVar = this.q;
        ((com.quizlet.features.achievements.notification.f) eVar.getValue()).f.f(getViewLifecycleOwner(), new com.quizlet.explanations.feedback.ui.fragments.c(13, new Function1(this) { // from class: com.quizlet.quizletandroid.ui.profile.d
            public final /* synthetic */ ProfileFragment b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function1
            public final Object invoke(Object obj) throws Exception {
                ProfileFragment profileFragment = this.b;
                switch (i3) {
                    case 0:
                        String str = ProfileFragment.x;
                        Context contextRequireContext = profileFragment.requireContext();
                        Intrinsics.checkNotNullExpressionValue(contextRequireContext, "requireContext(...)");
                        ((com.quizlet.features.infra.snackbar.m) obj).a(contextRequireContext);
                        return Unit.a;
                    case 1:
                        com.quizlet.features.achievements.notification.c cVar = (com.quizlet.features.achievements.notification.c) obj;
                        String str2 = ProfileFragment.x;
                        if (cVar instanceof com.quizlet.features.achievements.notification.a) {
                            ((D) profileFragment.J()).b.g(((com.quizlet.features.achievements.notification.a) cVar).a);
                        }
                        return Unit.a;
                    case 2:
                        l lVar = (l) obj;
                        String str3 = ProfileFragment.x;
                        if (lVar instanceof j) {
                            int i52 = SettingsActivity.p;
                            Context contextRequireContext2 = profileFragment.requireContext();
                            Intrinsics.checkNotNullExpressionValue(contextRequireContext2, "requireContext(...)");
                            profileFragment.startActivity(C2.c(contextRequireContext2));
                        } else if (lVar instanceof k) {
                            ((k) lVar).getClass();
                            com.quizlet.features.infra.models.upgrade.a aVar = com.quizlet.features.infra.models.upgrade.a.r;
                            String str4 = UpgradeActivity.v;
                            Context contextRequireContext3 = profileFragment.requireContext();
                            Intrinsics.checkNotNullExpressionValue(contextRequireContext3, "requireContext(...)");
                            profileFragment.startActivityForResult(AbstractC3242q6.i(contextRequireContext3, "chiclet", aVar), 224);
                        } else {
                            if (!(lVar instanceof i)) {
                                throw new NoWhenBranchMatchedException();
                            }
                            i iVar = (i) lVar;
                            Context contextRequireContext4 = profileFragment.requireContext();
                            String str5 = iVar.a;
                            int i6 = ChangeProfileImageActivity.q;
                            Intent intent = new Intent(contextRequireContext4, (Class<?>) ChangeProfileImageActivity.class);
                            intent.putExtra("EXTRA_PROFILE_IMAGE_ID", str5);
                            intent.putExtra("EXTRA_ALLOW_CUSTOM_IMAGES", iVar.b);
                            androidx.activity.result.b bVar2 = profileFragment.k;
                            if (bVar2 == null) {
                                Intrinsics.m("changeProfileImageResultLauncher");
                                throw null;
                            }
                            bVar2.a(intent);
                        }
                        return Unit.a;
                    case 3:
                        com.quizlet.quizletandroid.ui.profile.data.i iVar2 = (com.quizlet.quizletandroid.ui.profile.data.i) obj;
                        String str6 = ProfileFragment.x;
                        Intrinsics.d(iVar2);
                        if (!iVar2.d) {
                            Intrinsics.checkNotNullParameter(profileFragment, "<this>");
                            I activity2 = profileFragment.getActivity();
                            Intrinsics.e(activity2, "null cannot be cast to non-null type androidx.appcompat.app.AppCompatActivity");
                            com.bumptech.glide.c cVarR3 = ((AbstractActivityC0055k) activity2).r();
                            if (cVarR3 != null) {
                                cVarR3.k();
                            }
                            ViewGroup.LayoutParams layoutParams = ((D) profileFragment.J()).d.getLayoutParams();
                            Intrinsics.e(layoutParams, "null cannot be cast to non-null type android.view.ViewGroup.MarginLayoutParams");
                            ((ViewGroup.MarginLayoutParams) layoutParams).topMargin = 0;
                        }
                        Group buttonsGroup = ((D) profileFragment.J()).c;
                        Intrinsics.checkNotNullExpressionValue(buttonsGroup, "buttonsGroup");
                        boolean z = iVar2.e;
                        buttonsGroup.setVisibility(z ? 0 : 8);
                        TextView upgradeButton = ((D) profileFragment.J()).i;
                        Intrinsics.checkNotNullExpressionValue(upgradeButton, "upgradeButton");
                        upgradeButton.setVisibility((z && iVar2.f) ? 0 : 8);
                        profileFragment.U(iVar2.a, iVar2.b, z);
                        profileFragment.s = iVar2.c;
                        profileFragment.requireActivity().invalidateOptionsMenu();
                        return Unit.a;
                    default:
                        List list = (List) obj;
                        String str7 = ProfileFragment.x;
                        Intrinsics.d(list);
                        profileFragment.T(list, profileFragment.w);
                        return Unit.a;
                }
            }
        }));
        X().l.f(this, new com.quizlet.explanations.feedback.ui.fragments.c(13, new Function1(this) { // from class: com.quizlet.quizletandroid.ui.profile.d
            public final /* synthetic */ ProfileFragment b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function1
            public final Object invoke(Object obj) throws Exception {
                ProfileFragment profileFragment = this.b;
                switch (i) {
                    case 0:
                        String str = ProfileFragment.x;
                        Context contextRequireContext = profileFragment.requireContext();
                        Intrinsics.checkNotNullExpressionValue(contextRequireContext, "requireContext(...)");
                        ((com.quizlet.features.infra.snackbar.m) obj).a(contextRequireContext);
                        return Unit.a;
                    case 1:
                        com.quizlet.features.achievements.notification.c cVar = (com.quizlet.features.achievements.notification.c) obj;
                        String str2 = ProfileFragment.x;
                        if (cVar instanceof com.quizlet.features.achievements.notification.a) {
                            ((D) profileFragment.J()).b.g(((com.quizlet.features.achievements.notification.a) cVar).a);
                        }
                        return Unit.a;
                    case 2:
                        l lVar = (l) obj;
                        String str3 = ProfileFragment.x;
                        if (lVar instanceof j) {
                            int i52 = SettingsActivity.p;
                            Context contextRequireContext2 = profileFragment.requireContext();
                            Intrinsics.checkNotNullExpressionValue(contextRequireContext2, "requireContext(...)");
                            profileFragment.startActivity(C2.c(contextRequireContext2));
                        } else if (lVar instanceof k) {
                            ((k) lVar).getClass();
                            com.quizlet.features.infra.models.upgrade.a aVar = com.quizlet.features.infra.models.upgrade.a.r;
                            String str4 = UpgradeActivity.v;
                            Context contextRequireContext3 = profileFragment.requireContext();
                            Intrinsics.checkNotNullExpressionValue(contextRequireContext3, "requireContext(...)");
                            profileFragment.startActivityForResult(AbstractC3242q6.i(contextRequireContext3, "chiclet", aVar), 224);
                        } else {
                            if (!(lVar instanceof i)) {
                                throw new NoWhenBranchMatchedException();
                            }
                            i iVar = (i) lVar;
                            Context contextRequireContext4 = profileFragment.requireContext();
                            String str5 = iVar.a;
                            int i6 = ChangeProfileImageActivity.q;
                            Intent intent = new Intent(contextRequireContext4, (Class<?>) ChangeProfileImageActivity.class);
                            intent.putExtra("EXTRA_PROFILE_IMAGE_ID", str5);
                            intent.putExtra("EXTRA_ALLOW_CUSTOM_IMAGES", iVar.b);
                            androidx.activity.result.b bVar2 = profileFragment.k;
                            if (bVar2 == null) {
                                Intrinsics.m("changeProfileImageResultLauncher");
                                throw null;
                            }
                            bVar2.a(intent);
                        }
                        return Unit.a;
                    case 3:
                        com.quizlet.quizletandroid.ui.profile.data.i iVar2 = (com.quizlet.quizletandroid.ui.profile.data.i) obj;
                        String str6 = ProfileFragment.x;
                        Intrinsics.d(iVar2);
                        if (!iVar2.d) {
                            Intrinsics.checkNotNullParameter(profileFragment, "<this>");
                            I activity2 = profileFragment.getActivity();
                            Intrinsics.e(activity2, "null cannot be cast to non-null type androidx.appcompat.app.AppCompatActivity");
                            com.bumptech.glide.c cVarR3 = ((AbstractActivityC0055k) activity2).r();
                            if (cVarR3 != null) {
                                cVarR3.k();
                            }
                            ViewGroup.LayoutParams layoutParams = ((D) profileFragment.J()).d.getLayoutParams();
                            Intrinsics.e(layoutParams, "null cannot be cast to non-null type android.view.ViewGroup.MarginLayoutParams");
                            ((ViewGroup.MarginLayoutParams) layoutParams).topMargin = 0;
                        }
                        Group buttonsGroup = ((D) profileFragment.J()).c;
                        Intrinsics.checkNotNullExpressionValue(buttonsGroup, "buttonsGroup");
                        boolean z = iVar2.e;
                        buttonsGroup.setVisibility(z ? 0 : 8);
                        TextView upgradeButton = ((D) profileFragment.J()).i;
                        Intrinsics.checkNotNullExpressionValue(upgradeButton, "upgradeButton");
                        upgradeButton.setVisibility((z && iVar2.f) ? 0 : 8);
                        profileFragment.U(iVar2.a, iVar2.b, z);
                        profileFragment.s = iVar2.c;
                        profileFragment.requireActivity().invalidateOptionsMenu();
                        return Unit.a;
                    default:
                        List list = (List) obj;
                        String str7 = ProfileFragment.x;
                        Intrinsics.d(list);
                        profileFragment.T(list, profileFragment.w);
                        return Unit.a;
                }
            }
        }));
        com.quizlet.infra.legacysyncengine.orm.b bVar2 = new com.quizlet.infra.legacysyncengine.orm.b(Models.STUDY_SET);
        Relationship<DBStudySet, DBUser> relationship = DBStudySetFields.CREATOR;
        bVar2.b(Long.valueOf(W()), relationship);
        bVar2.e(relationship);
        com.quizlet.infra.legacysyncengine.orm.query.a aVarA = bVar2.a();
        com.quizlet.infra.legacysyncengine.net.c cVar = this.l;
        if (cVar == null) {
            Intrinsics.m("loader");
            throw null;
        }
        com.quizlet.infra.legacysyncengine.datasources.o oVar = new com.quizlet.infra.legacysyncengine.datasources.o(cVar, aVarA);
        Intrinsics.checkNotNullParameter(oVar, "<set-?>");
        this.j = oVar;
        U(null, null, false);
        ((D) J()).b.setOnAchievementEventListener((com.quizlet.features.achievements.notification.f) eVar.getValue());
        ((com.quizlet.features.achievements.notification.f) eVar.getValue()).A();
        EventLogger eventLogger = this.m;
        if (eventLogger == null) {
            Intrinsics.m("eventLogger");
            throw null;
        }
        eventLogger.J(2, W());
        q.b.getClass();
        T(B.j(q.d, q.f), this.w);
    }

    @Override // com.quizlet.baseui.interfaces.a
    public final void r() {
        X().D();
    }
}

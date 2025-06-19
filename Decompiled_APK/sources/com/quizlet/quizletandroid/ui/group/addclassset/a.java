package com.quizlet.quizletandroid.ui.group.addclassset;

import android.content.Context;
import android.os.Bundle;
import android.util.SparseArray;
import androidx.fragment.app.AbstractC1136h0;
import androidx.fragment.app.C1121a;
import androidx.fragment.app.Fragment;
import androidx.fragment.app.p0;
import androidx.viewpager.widget.ViewPager;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3206m6;
import com.quizlet.baseui.base.BaseFragment;
import com.quizlet.features.achievements.ui.AchievementsFragment;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.ui.profile.ProfileFragment;
import com.quizlet.quizletandroid.ui.profile.ProfileUserClassListFragment;
import com.quizlet.quizletandroid.ui.profile.UserFolderListFragment;
import com.quizlet.quizletandroid.ui.profile.UserSetListFragment;
import com.quizlet.quizletandroid.ui.profile.q;
import java.util.ArrayList;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Pair;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a extends p0 {
    public final /* synthetic */ int j = 0;
    public final Cloneable k;
    public final Object l;

    public a(AddClassSetActivity addClassSetActivity, AbstractC1136h0 abstractC1136h0) {
        super(0, abstractC1136h0);
        this.k = new SparseArray();
        this.l = addClassSetActivity.getApplicationContext();
    }

    @Override // androidx.fragment.app.p0, androidx.viewpager.widget.a
    public void a(ViewPager viewPager, int i, Object obj) {
        switch (this.j) {
            case 0:
                super.a(viewPager, i, obj);
                if (i >= 3) {
                    Fragment fragment = (Fragment) obj;
                    AbstractC1136h0 fragmentManager = fragment.getFragmentManager();
                    fragmentManager.getClass();
                    C1121a c1121a = new C1121a(fragmentManager);
                    c1121a.k(fragment);
                    c1121a.g();
                    break;
                }
                break;
            default:
                super.a(viewPager, i, obj);
                break;
        }
    }

    @Override // androidx.viewpager.widget.a
    public final int c() {
        switch (this.j) {
            case 0:
                return 3;
            default:
                return ((ArrayList) this.k).size();
        }
    }

    @Override // androidx.viewpager.widget.a
    public int d(Object object) {
        switch (this.j) {
            case 1:
                Intrinsics.checkNotNullParameter(object, "object");
                return -2;
            default:
                return super.d(object);
        }
    }

    @Override // androidx.viewpager.widget.a
    public final String e(int i) {
        int i2;
        switch (this.j) {
            case 0:
                if (i == 0) {
                    i2 = R.string.add_set_created_sets_tab;
                } else if (i == 1) {
                    i2 = R.string.add_set_studied_sets_tab;
                } else {
                    if (i != 2) {
                        throw new IndexOutOfBoundsException(android.support.v4.media.session.a.f(i, "No page title defined for position: "));
                    }
                    i2 = R.string.add_set_classes_sets_tab;
                }
                return ((Context) this.l).getString(i2);
            default:
                String string = ((ProfileFragment) this.l).getString(((q) ((ArrayList) this.k).get(i)).a);
                Intrinsics.checkNotNullExpressionValue(string, "getString(...)");
                return string;
        }
    }

    @Override // androidx.fragment.app.p0, androidx.viewpager.widget.a
    public Object f(ViewPager viewPager, int i) {
        switch (this.j) {
            case 0:
                BaseFragment baseFragment = (BaseFragment) super.f(viewPager, i);
                ((SparseArray) this.k).put(i, baseFragment);
                return baseFragment;
            default:
                return super.f(viewPager, i);
        }
    }

    @Override // androidx.fragment.app.p0
    public final Fragment j(int i) {
        switch (this.j) {
            case 0:
                if (i == 0) {
                    return new CreatedUserSetListFragment();
                }
                if (i == 1) {
                    return new StudiedUserSetListFragment();
                }
                if (i != 2) {
                    return null;
                }
                return new ClassesUserSetListFragment();
            default:
                int iOrdinal = ((q) ((ArrayList) this.k).get(i)).ordinal();
                ProfileFragment profileFragment = (ProfileFragment) this.l;
                if (iOrdinal == 0) {
                    String str = AchievementsFragment.l;
                    String str2 = (String) profileFragment.v.getValue();
                    AchievementsFragment achievementsFragment = new AchievementsFragment();
                    achievementsFragment.setArguments(AbstractC3206m6.a(new Pair("badgeId", str2)));
                    return achievementsFragment;
                }
                if (iOrdinal == 1) {
                    UserSetListFragment userSetListFragment = new UserSetListFragment();
                    Intrinsics.checkNotNullExpressionValue(userSetListFragment, "newInstance(...)");
                    return userSetListFragment;
                }
                if (iOrdinal == 2) {
                    String str3 = ProfileFragment.x;
                    long jW = profileFragment.W();
                    ProfileUserClassListFragment profileUserClassListFragment = new ProfileUserClassListFragment();
                    profileUserClassListFragment.setArguments(AbstractC3206m6.a(new Pair("user_id", Long.valueOf(jW))));
                    return profileUserClassListFragment;
                }
                if (iOrdinal != 3) {
                    throw new NoWhenBranchMatchedException();
                }
                String str4 = UserFolderListFragment.z;
                String str5 = ProfileFragment.x;
                long jW2 = profileFragment.W();
                Bundle bundle = new Bundle();
                bundle.putLong("userId", jW2);
                UserFolderListFragment userFolderListFragment = new UserFolderListFragment();
                userFolderListFragment.setArguments(bundle);
                return userFolderListFragment;
        }
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public a(ProfileFragment profileFragment, AbstractC1136h0 fm, ArrayList content) {
        super(0, fm);
        Intrinsics.checkNotNullParameter(fm, "fm");
        Intrinsics.checkNotNullParameter(content, "content");
        this.l = profileFragment;
        this.k = content;
    }
}

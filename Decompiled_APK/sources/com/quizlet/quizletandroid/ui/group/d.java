package com.quizlet.quizletandroid.ui.group;

import androidx.fragment.app.AbstractC1136h0;
import androidx.fragment.app.Fragment;
import androidx.fragment.app.p0;
import com.quizlet.quizletandroid.ui.group.classcontent.ClassContentListFragment;
import com.quizlet.quizletandroid.ui.group.classuser.ClassUserListFragment;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class d extends p0 {
    public final /* synthetic */ GroupFragment j;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public d(GroupFragment groupFragment, AbstractC1136h0 fm) {
        super(1, fm);
        Intrinsics.checkNotNullParameter(fm, "fm");
        this.j = groupFragment;
    }

    @Override // androidx.viewpager.widget.a
    public final int c() {
        return GroupFragment.W.length;
    }

    @Override // androidx.viewpager.widget.a
    public final String e(int i) {
        String string = this.j.getString(GroupFragment.W[i]);
        Intrinsics.checkNotNullExpressionValue(string, "getString(...)");
        return string;
    }

    @Override // androidx.fragment.app.p0
    public final Fragment j(int i) {
        if (i == 0) {
            String str = ClassContentListFragment.n;
            return new ClassContentListFragment();
        }
        if (i != 1) {
            throw new IndexOutOfBoundsException(android.support.v4.media.session.a.f(i, "No fragment defined for num: "));
        }
        ClassUserListFragment classUserListFragment = new ClassUserListFragment();
        Intrinsics.checkNotNullExpressionValue(classUserListFragment, "newInstance(...)");
        return classUserListFragment;
    }
}

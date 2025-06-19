package com.quizlet.quizletandroid.ui.search;

import android.os.Bundle;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import androidx.activity.v;
import androidx.fragment.app.AbstractC1136h0;
import androidx.fragment.app.C1121a;
import com.quizlet.ads.ui.activity.d;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.databinding.L;
import com.quizlet.search.NewSearchFragment;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes3.dex */
public final class SearchActivity extends d {
    public static final String q;

    static {
        Intrinsics.checkNotNullExpressionValue("SearchActivity", "getSimpleName(...)");
        q = "SearchActivity";
    }

    public SearchActivity() {
        super(6);
    }

    @Override // com.quizlet.baseui.base.b
    public final String D() {
        return q;
    }

    @Override // com.quizlet.baseui.base.b
    public final boolean H() {
        return false;
    }

    @Override // com.quizlet.baseui.base.f
    public final androidx.viewbinding.a N() {
        View viewInflate = getLayoutInflater().inflate(R.layout.search_activity, (ViewGroup) null, false);
        if (viewInflate == null) {
            throw new NullPointerException("rootView");
        }
        FrameLayout frameLayout = (FrameLayout) viewInflate;
        L l = new L(frameLayout, frameLayout, 1);
        Intrinsics.checkNotNullExpressionValue(l, "inflate(...)");
        return l;
    }

    @Override // com.quizlet.ads.ui.activity.d, com.quizlet.baseui.base.f, com.quizlet.baseui.base.b, androidx.fragment.app.I, androidx.activity.s, androidx.core.app.AbstractActivityC1021h, android.app.Activity
    public final void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        v.b(this, null, 3);
        String stringExtra = getIntent().getStringExtra("searchQuery");
        NewSearchFragment newSearchFragment = new NewSearchFragment();
        Bundle bundle2 = new Bundle();
        bundle2.putString("searchQuery", stringExtra);
        bundle2.putBoolean("hasBottomBar", false);
        newSearchFragment.setArguments(bundle2);
        String str = NewSearchFragment.o;
        AbstractC1136h0 supportFragmentManager = getSupportFragmentManager();
        supportFragmentManager.getClass();
        C1121a c1121a = new C1121a(supportFragmentManager);
        c1121a.l(R.id.searchFragmentContainer, newSearchFragment, str);
        c1121a.g();
    }
}

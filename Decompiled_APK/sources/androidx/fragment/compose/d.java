package androidx.fragment.compose;

import android.content.Context;
import androidx.fragment.app.FragmentContainerView;
import kotlin.jvm.functions.Function1;

/* loaded from: classes.dex */
public final class d implements Function1 {
    public final int a;
    public FragmentContainerView b;

    public d(int i) {
        this.a = i;
    }

    public final FragmentContainerView a() {
        FragmentContainerView fragmentContainerView = this.b;
        if (fragmentContainerView != null) {
            return fragmentContainerView;
        }
        throw new IllegalStateException(android.support.v4.media.session.a.r(new StringBuilder("AndroidView has not created a container for "), this.a, " yet").toString());
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        FragmentContainerView fragmentContainerView = new FragmentContainerView((Context) obj);
        fragmentContainerView.setId(this.a);
        this.b = fragmentContainerView;
        return fragmentContainerView;
    }
}

package leakcanary.internal;

import androidx.fragment.app.AbstractC1124b0;
import androidx.fragment.app.AbstractC1136h0;
import androidx.fragment.app.Fragment;
import com.quizlet.quizletandroid.ui.studymodes.match.fragment.t;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class b extends AbstractC1124b0 {
    public final /* synthetic */ t a;

    public b(t tVar) {
        this.a = tVar;
    }

    @Override // androidx.fragment.app.AbstractC1124b0
    public final void c(AbstractC1136h0 fm, Fragment fragment) {
        Intrinsics.f(fm, "fm");
        Intrinsics.f(fragment, "fragment");
        this.a.invoke();
    }
}

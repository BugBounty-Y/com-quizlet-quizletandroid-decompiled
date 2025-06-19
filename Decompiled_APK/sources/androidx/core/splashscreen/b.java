package androidx.core.splashscreen;

import android.content.res.Resources;
import android.util.TypedValue;
import android.view.ViewGroup;
import com.airbnb.lottie.network.d;
import com.quizlet.quizletandroid.ui.RootActivity;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class b extends d {
    public final a c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b(RootActivity activity) {
        super(activity);
        Intrinsics.checkNotNullParameter(activity, "activity");
        this.c = new a(this, activity);
    }

    @Override // com.airbnb.lottie.network.d
    public final void l() {
        RootActivity rootActivity = (RootActivity) this.b;
        Resources.Theme theme = rootActivity.getTheme();
        Intrinsics.checkNotNullExpressionValue(theme, "activity.theme");
        q(theme, new TypedValue());
        ((ViewGroup) rootActivity.getWindow().getDecorView()).setOnHierarchyChangeListener(this.c);
    }
}

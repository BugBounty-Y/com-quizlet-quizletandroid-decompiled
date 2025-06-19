package com.quizlet.quizletandroid.ui.preview.viewmodel;

import android.content.SharedPreferences;
import androidx.lifecycle.X;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class f implements io.reactivex.rxjava3.functions.d {
    public final /* synthetic */ g a;
    public final /* synthetic */ int b;

    public f(g gVar, int i) {
        this.a = gVar;
        this.b = i;
    }

    @Override // io.reactivex.rxjava3.functions.d
    public final void accept(Object obj) {
        List previews = (List) obj;
        Intrinsics.checkNotNullParameter(previews, "previews");
        g gVar = this.a;
        gVar.f.j(new c(previews));
        com.quizlet.quizletandroid.ui.preview.dataclass.g gVar2 = gVar.d;
        boolean z = ((SharedPreferences) gVar2.a.getValue()).getBoolean("HAS_SEEN_ONBOARDING", false);
        X x = gVar.g;
        if (z) {
            x.j(Boolean.FALSE);
        } else {
            assistantMode.refactored.a.p((SharedPreferences) gVar2.a.getValue(), "HAS_SEEN_ONBOARDING", true);
            x.j(Boolean.TRUE);
        }
        gVar.i.j(Integer.valueOf(this.b));
    }
}

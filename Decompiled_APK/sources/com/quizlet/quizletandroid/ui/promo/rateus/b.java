package com.quizlet.quizletandroid.ui.promo.rateus;

import android.content.SharedPreferences;
import com.quizlet.eventlogger.EventLogger;
import com.quizlet.quizletandroid.ui.startpage.nav2.OldHomeFragment;
import java.lang.ref.WeakReference;

/* loaded from: classes3.dex */
public final class b {
    public final SharedPreferences a;
    public final EventLogger b;
    public final com.quizlet.ads.d c;
    public final androidx.work.impl.model.c d;
    public final WeakReference e;

    public b(long j, OldHomeFragment oldHomeFragment, SharedPreferences sharedPreferences, EventLogger eventLogger, androidx.work.impl.model.c cVar) {
        this.e = new WeakReference(oldHomeFragment);
        this.a = sharedPreferences;
        this.b = eventLogger;
        this.c = new com.quizlet.ads.d(j, sharedPreferences);
        this.d = cVar;
    }

    public final void a() {
        a aVar = (a) this.e.get();
        if (aVar == null) {
            return;
        }
        assistantMode.refactored.a.p(this.a, "RateUsPromoDismissed", true);
        ((OldHomeFragment) aVar).a0(false);
    }
}

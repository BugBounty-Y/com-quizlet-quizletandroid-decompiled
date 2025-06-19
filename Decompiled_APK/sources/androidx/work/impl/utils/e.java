package androidx.work.impl.utils;

import android.content.Context;
import androidx.work.impl.WorkDatabase;
import com.airbnb.lottie.LottieAnimationView;
import java.util.concurrent.Callable;

/* loaded from: classes.dex */
public final /* synthetic */ class e implements Callable {
    public final /* synthetic */ int a;
    public final /* synthetic */ int b;
    public final /* synthetic */ Object c;

    public /* synthetic */ e(Object obj, int i, int i2) {
        this.a = i2;
        this.c = obj;
        this.b = i;
    }

    @Override // java.util.concurrent.Callable
    public final Object call() {
        switch (this.a) {
            case 0:
                com.google.android.gms.internal.instantapps.a aVar = (com.google.android.gms.internal.instantapps.a) this.c;
                WorkDatabase workDatabase = (WorkDatabase) aVar.b;
                Long lP = workDatabase.l().p("next_job_scheduler_id");
                int i = 0;
                int iLongValue = lP != null ? (int) lP.longValue() : 0;
                workDatabase.l().t(new androidx.work.impl.model.d(Long.valueOf(iLongValue == Integer.MAX_VALUE ? 0 : iLongValue + 1), "next_job_scheduler_id"));
                if (iLongValue < 0 || iLongValue > this.b) {
                    ((WorkDatabase) aVar.b).l().t(new androidx.work.impl.model.d(Long.valueOf(1), "next_job_scheduler_id"));
                } else {
                    i = iLongValue;
                }
                return Integer.valueOf(i);
            default:
                LottieAnimationView lottieAnimationView = (LottieAnimationView) this.c;
                boolean z = lottieAnimationView.m;
                int i2 = this.b;
                if (!z) {
                    return com.airbnb.lottie.l.g(lottieAnimationView.getContext(), null, i2);
                }
                Context context = lottieAnimationView.getContext();
                return com.airbnb.lottie.l.g(context, com.airbnb.lottie.l.l(context, i2), i2);
        }
    }
}

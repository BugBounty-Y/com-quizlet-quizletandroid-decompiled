package org.prebid.mobile.rendering.utils.helpers;

import android.os.Handler;
import android.os.Looper;
import com.quizlet.infra.legacysyncengine.tasks.parse.b;
import org.prebid.mobile.LogUtil;
import org.prebid.mobile.rendering.bidding.loader.BidLoader;

/* loaded from: classes3.dex */
public class RefreshTimerTask {
    public final b b;
    public final Runnable c = new Runnable() { // from class: org.prebid.mobile.rendering.utils.helpers.RefreshTimerTask.1
        @Override // java.lang.Runnable
        public final void run() {
            b bVar = RefreshTimerTask.this.b;
            if (bVar == null) {
                LogUtil.b("RefreshTimerTask", "Failed to notify refreshTriggerListener. refreshTriggerListener instance is null");
                return;
            }
            BidLoader bidLoader = (BidLoader) bVar.b;
            if (bidLoader.a == null) {
                LogUtil.b("BidLoader", "handleRefresh(): Failure. AdConfiguration is null");
            } else if (bidLoader.e == null) {
                LogUtil.b("BidLoader", "RefreshListener is null. No refresh or load will be performed.");
            } else {
                LogUtil.e(3, "BidLoader", "refresh triggered: load() being called ");
                bidLoader.b();
            }
        }
    };
    public final Handler a = new Handler(Looper.getMainLooper());

    public RefreshTimerTask(b bVar) {
        this.b = bVar;
    }
}

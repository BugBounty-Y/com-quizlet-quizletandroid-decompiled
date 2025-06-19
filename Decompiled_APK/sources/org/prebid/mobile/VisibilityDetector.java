package org.prebid.mobile;

import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.concurrent.ScheduledExecutorService;

/* loaded from: classes3.dex */
class VisibilityDetector {
    public boolean a;
    public WeakReference b;
    public ArrayList c;
    public Runnable d;
    public ScheduledExecutorService e;

    public interface VisibilityListener {
    }
}

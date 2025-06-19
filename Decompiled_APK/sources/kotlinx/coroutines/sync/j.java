package kotlinx.coroutines.sync;

import com.android.billingclient.api.C1472a;

/* loaded from: classes3.dex */
public abstract class j {
    public static final int a = kotlinx.coroutines.internal.b.k(100, 12, "kotlinx.coroutines.semaphore.maxSpinCycles");
    public static final C1472a b = new C1472a("PERMIT", 2);
    public static final C1472a c = new C1472a("TAKEN", 2);
    public static final C1472a d = new C1472a("BROKEN", 2);
    public static final C1472a e = new C1472a("CANCELLED", 2);
    public static final int f = kotlinx.coroutines.internal.b.k(16, 12, "kotlinx.coroutines.semaphore.segmentSize");
}

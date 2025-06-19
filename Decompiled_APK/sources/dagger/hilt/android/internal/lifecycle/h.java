package dagger.hilt.android.internal.lifecycle;

import android.os.Looper;
import com.google.android.gms.internal.mlkit_vision_barcode.O6;
import java.util.HashSet;
import java.util.Iterator;

/* loaded from: classes3.dex */
public final class h {
    public final HashSet a = new HashSet();

    public final void a() {
        if (O6.a == null) {
            O6.a = Looper.getMainLooper().getThread();
        }
        if (Thread.currentThread() != O6.a) {
            throw new IllegalStateException("Must be called on the Main thread.");
        }
        Iterator it2 = this.a.iterator();
        if (it2.hasNext()) {
            throw android.support.v4.media.session.a.d(it2);
        }
    }
}

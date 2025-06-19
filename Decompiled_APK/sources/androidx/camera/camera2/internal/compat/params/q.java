package androidx.camera.camera2.internal.compat.params;

import android.hardware.camera2.params.OutputConfiguration;
import android.os.Build;
import androidx.camera.camera2.internal.L;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

/* loaded from: classes.dex */
public final class q {
    public final p a;

    public q(ArrayList arrayList, androidx.camera.core.impl.utils.executor.k kVar, L l) {
        if (Build.VERSION.SDK_INT < 28) {
            this.a = new o(arrayList, kVar, l);
        } else {
            this.a = new n(arrayList, kVar, l);
        }
    }

    public static ArrayList a(List list) {
        ArrayList arrayList = new ArrayList(list.size());
        Iterator it2 = list.iterator();
        while (it2.hasNext()) {
            arrayList.add((OutputConfiguration) ((h) it2.next()).a.a());
        }
        return arrayList;
    }

    public final boolean equals(Object obj) {
        if (!(obj instanceof q)) {
            return false;
        }
        return this.a.equals(((q) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }
}

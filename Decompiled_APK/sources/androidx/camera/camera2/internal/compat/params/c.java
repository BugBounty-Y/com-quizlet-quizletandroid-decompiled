package androidx.camera.camera2.internal.compat.params;

import android.hardware.camera2.params.DynamicRangeProfiles;
import androidx.camera.core.C0196t;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3242q6;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

/* loaded from: classes.dex */
public final class c implements b {
    public final DynamicRangeProfiles a;

    public c(Object obj) {
        this.a = (DynamicRangeProfiles) obj;
    }

    public static Set d(Set set) {
        if (set.isEmpty()) {
            return Collections.EMPTY_SET;
        }
        HashSet hashSet = new HashSet(set.size());
        Iterator it2 = set.iterator();
        while (it2.hasNext()) {
            Long l = (Long) it2.next();
            long jLongValue = l.longValue();
            C0196t c0196t = (C0196t) a.a.get(l);
            AbstractC3242q6.g(c0196t, "Dynamic range profile cannot be converted to a DynamicRange object: " + jLongValue);
            hashSet.add(c0196t);
        }
        return Collections.unmodifiableSet(hashSet);
    }

    @Override // androidx.camera.camera2.internal.compat.params.b
    public final DynamicRangeProfiles a() {
        return this.a;
    }

    @Override // androidx.camera.camera2.internal.compat.params.b
    public final Set b() {
        return d(this.a.getSupportedProfiles());
    }

    @Override // androidx.camera.camera2.internal.compat.params.b
    public final Set c(C0196t c0196t) {
        Long lA = a.a(c0196t, this.a);
        AbstractC3242q6.c("DynamicRange is not supported: " + c0196t, lA != null);
        return d(this.a.getProfileCaptureRequestConstraints(lA.longValue()));
    }
}

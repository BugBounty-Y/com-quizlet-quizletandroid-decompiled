package androidx.camera.camera2.internal.compat.params;

import android.hardware.camera2.CameraCaptureSession;
import android.hardware.camera2.CaptureRequest;
import androidx.camera.camera2.internal.L;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.Executor;

/* loaded from: classes.dex */
public final class o implements p {
    public final List a;
    public final L b;
    public final androidx.camera.core.impl.utils.executor.k c;
    public g d = null;

    public o(ArrayList arrayList, androidx.camera.core.impl.utils.executor.k kVar, L l) {
        this.a = Collections.unmodifiableList(new ArrayList(arrayList));
        this.b = l;
        this.c = kVar;
    }

    @Override // androidx.camera.camera2.internal.compat.params.p
    public final Object a() {
        return null;
    }

    @Override // androidx.camera.camera2.internal.compat.params.p
    public final void b(g gVar) {
        this.d = gVar;
    }

    @Override // androidx.camera.camera2.internal.compat.params.p
    public final g c() {
        return this.d;
    }

    @Override // androidx.camera.camera2.internal.compat.params.p
    public final Executor d() {
        return this.c;
    }

    @Override // androidx.camera.camera2.internal.compat.params.p
    public final int e() {
        return 0;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof o) {
            o oVar = (o) obj;
            if (Objects.equals(this.d, oVar.d)) {
                List list = this.a;
                int size = list.size();
                List list2 = oVar.a;
                if (size == list2.size()) {
                    for (int i = 0; i < list.size(); i++) {
                        if (((h) list.get(i)).equals(list2.get(i))) {
                        }
                    }
                    return true;
                }
            }
        }
        return false;
    }

    @Override // androidx.camera.camera2.internal.compat.params.p
    public final CameraCaptureSession.StateCallback f() {
        return this.b;
    }

    @Override // androidx.camera.camera2.internal.compat.params.p
    public final List g() {
        return this.a;
    }

    @Override // androidx.camera.camera2.internal.compat.params.p
    public final void h(CaptureRequest captureRequest) {
    }

    public final int hashCode() {
        int iHashCode = this.a.hashCode() ^ 31;
        int i = (iHashCode << 5) - iHashCode;
        g gVar = this.d;
        int iHashCode2 = (gVar == null ? 0 : gVar.a.a.hashCode()) ^ i;
        return (iHashCode2 << 5) - iHashCode2;
    }
}

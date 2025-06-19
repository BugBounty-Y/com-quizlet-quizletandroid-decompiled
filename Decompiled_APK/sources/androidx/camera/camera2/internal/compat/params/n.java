package androidx.camera.camera2.internal.compat.params;

import android.hardware.camera2.CameraCaptureSession;
import android.hardware.camera2.CaptureRequest;
import android.hardware.camera2.params.OutputConfiguration;
import android.hardware.camera2.params.SessionConfiguration;
import android.os.Build;
import androidx.camera.camera2.internal.L;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.Executor;

/* loaded from: classes.dex */
public final class n implements p {
    public final SessionConfiguration a;
    public final List b;

    public n(ArrayList arrayList, androidx.camera.core.impl.utils.executor.k kVar, L l) {
        h hVar;
        SessionConfiguration sessionConfiguration = new SessionConfiguration(0, q.a(arrayList), kVar, l);
        this.a = sessionConfiguration;
        List<OutputConfiguration> outputConfigurations = sessionConfiguration.getOutputConfigurations();
        ArrayList arrayList2 = new ArrayList(outputConfigurations.size());
        for (OutputConfiguration outputConfiguration : outputConfigurations) {
            if (outputConfiguration == null) {
                hVar = null;
            } else {
                int i = Build.VERSION.SDK_INT;
                hVar = new h(i >= 33 ? new m(outputConfiguration) : i >= 28 ? new l(new k(outputConfiguration)) : new j(new i(outputConfiguration)));
            }
            arrayList2.add(hVar);
        }
        this.b = Collections.unmodifiableList(arrayList2);
    }

    @Override // androidx.camera.camera2.internal.compat.params.p
    public final Object a() {
        return this.a;
    }

    @Override // androidx.camera.camera2.internal.compat.params.p
    public final void b(g gVar) {
        this.a.setInputConfiguration(gVar.a.a);
    }

    @Override // androidx.camera.camera2.internal.compat.params.p
    public final g c() {
        return g.a(this.a.getInputConfiguration());
    }

    @Override // androidx.camera.camera2.internal.compat.params.p
    public final Executor d() {
        return this.a.getExecutor();
    }

    @Override // androidx.camera.camera2.internal.compat.params.p
    public final int e() {
        return this.a.getSessionType();
    }

    public final boolean equals(Object obj) {
        if (obj instanceof n) {
            return Objects.equals(this.a, ((n) obj).a);
        }
        return false;
    }

    @Override // androidx.camera.camera2.internal.compat.params.p
    public final CameraCaptureSession.StateCallback f() {
        return this.a.getStateCallback();
    }

    @Override // androidx.camera.camera2.internal.compat.params.p
    public final List g() {
        return this.b;
    }

    @Override // androidx.camera.camera2.internal.compat.params.p
    public final void h(CaptureRequest captureRequest) {
        this.a.setSessionParameters(captureRequest);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }
}

package androidx.camera.camera2.internal.compat;

import android.hardware.camera2.CameraAccessException;
import android.hardware.camera2.CameraDevice;
import android.hardware.camera2.params.InputConfiguration;
import android.os.Handler;
import androidx.appcompat.app.y;
import androidx.camera.camera2.internal.AbstractC0147y;
import com.google.android.gms.internal.measurement.AbstractC3053s1;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

/* loaded from: classes.dex */
public class m extends y {
    public void v(androidx.camera.camera2.internal.compat.params.q qVar) throws CameraAccessException, CameraAccessExceptionCompat {
        CameraDevice cameraDevice = (CameraDevice) this.b;
        cameraDevice.getClass();
        androidx.camera.camera2.internal.compat.params.p pVar = qVar.a;
        pVar.f().getClass();
        List listG = pVar.g();
        if (listG == null) {
            throw new IllegalArgumentException("Invalid output configurations");
        }
        if (pVar.d() == null) {
            throw new IllegalArgumentException("Invalid executor");
        }
        String id = cameraDevice.getId();
        Iterator it2 = listG.iterator();
        while (it2.hasNext()) {
            String strB = ((androidx.camera.camera2.internal.compat.params.h) it2.next()).a.b();
            if (strB != null && !strB.isEmpty()) {
                AbstractC3053s1.h("CameraDeviceCompat", AbstractC0147y.e("Camera ", id, ": Camera doesn't support physicalCameraId ", strB, ". Ignoring."));
            }
        }
        f fVar = new f(pVar.d(), pVar.f());
        List listG2 = pVar.g();
        com.google.android.gms.auth.api.signin.internal.h hVar = (com.google.android.gms.auth.api.signin.internal.h) this.c;
        hVar.getClass();
        androidx.camera.camera2.internal.compat.params.g gVarC = pVar.c();
        Handler handler = (Handler) hVar.b;
        try {
            if (gVarC != null) {
                InputConfiguration inputConfiguration = gVarC.a.a;
                inputConfiguration.getClass();
                cameraDevice.createReprocessableCaptureSessionByConfigurations(inputConfiguration, androidx.camera.camera2.internal.compat.params.q.a(listG2), fVar, handler);
            } else {
                if (pVar.e() != 1) {
                    cameraDevice.createCaptureSessionByOutputConfigurations(androidx.camera.camera2.internal.compat.params.q.a(listG2), fVar, handler);
                    return;
                }
                ArrayList arrayList = new ArrayList(listG2.size());
                Iterator it3 = listG2.iterator();
                while (it3.hasNext()) {
                    arrayList.add(((androidx.camera.camera2.internal.compat.params.h) it3.next()).a.c());
                }
                cameraDevice.createConstrainedHighSpeedCaptureSession(arrayList, fVar, handler);
            }
        } catch (CameraAccessException e) {
            throw new CameraAccessExceptionCompat(e);
        }
    }
}

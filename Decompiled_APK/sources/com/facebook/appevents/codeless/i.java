package com.facebook.appevents.codeless;

import android.hardware.camera2.CameraAccessException;
import android.hardware.camera2.CameraDevice;
import android.hardware.camera2.CaptureRequest;
import android.hardware.camera2.TotalCaptureResult;
import android.util.Range;
import android.view.Surface;
import androidx.appcompat.app.L;
import androidx.camera.core.impl.C0162c;
import androidx.camera.core.impl.C0163c0;
import androidx.camera.core.impl.C0168g;
import androidx.camera.core.impl.F;
import androidx.camera.core.impl.InterfaceC0177p;
import androidx.camera.core.impl.J;
import com.bumptech.glide.load.engine.n;
import com.google.android.gms.internal.measurement.AbstractC3053s1;
import com.google.android.gms.internal.mlkit_vision_barcode.C3268u;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3531s4;
import com.google.common.collect.C3922e;
import com.google.common.collect.s;
import com.google.common.collect.x;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public abstract class i {
    /* JADX WARN: Removed duplicated region for block: B:23:0x004b  */
    /* JADX WARN: Removed duplicated region for block: B:24:0x004d  */
    /* JADX WARN: Removed duplicated region for block: B:25:0x0050  */
    /* JADX WARN: Removed duplicated region for block: B:28:0x0070  */
    /* JADX WARN: Removed duplicated region for block: B:29:0x0074  */
    /* JADX WARN: Removed duplicated region for block: B:34:0x0095  */
    /* JADX WARN: Removed duplicated region for block: B:38:0x00e2  */
    /* JADX WARN: Removed duplicated region for block: B:40:? A[RETURN, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void a(int r23, int r24, androidx.compose.runtime.InterfaceC0806l r25, androidx.compose.ui.q r26, java.lang.String r27) {
        /*
            Method dump skipped, instructions count: 241
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.facebook.appevents.codeless.i.a(int, int, androidx.compose.runtime.l, androidx.compose.ui.q, java.lang.String):void");
    }

    public static final void b(List list, Object obj, boolean z) {
        Intrinsics.checkNotNullParameter(list, "<this>");
        if (z) {
            list.add(obj);
        }
    }

    public static void c(CaptureRequest.Builder builder, C0163c0 c0163c0) {
        L lH = com.google.firebase.platforminfo.c.l(c0163c0).h();
        for (C0162c c0162c : lH.f()) {
            CaptureRequest.Key key = c0162c.c;
            try {
                builder.set(key, lH.e(c0162c));
            } catch (IllegalArgumentException unused) {
                AbstractC3053s1.c("Camera2CaptureRequestBuilder", "CaptureRequest.Key is not supported: " + key);
            }
        }
    }

    public static void d(CaptureRequest.Builder builder, int i, androidx.camera.camera2.internal.compat.workaround.a aVar) {
        Map mapUnmodifiableMap;
        if (i == 3 && aVar.a) {
            HashMap map = new HashMap();
            map.put(CaptureRequest.CONTROL_CAPTURE_INTENT, 1);
            mapUnmodifiableMap = Collections.unmodifiableMap(map);
        } else {
            if (i != 4) {
                aVar.getClass();
            } else if (aVar.b) {
                HashMap map2 = new HashMap();
                map2.put(CaptureRequest.CONTROL_CAPTURE_INTENT, 2);
                mapUnmodifiableMap = Collections.unmodifiableMap(map2);
            }
            mapUnmodifiableMap = Collections.EMPTY_MAP;
        }
        for (Map.Entry entry : mapUnmodifiableMap.entrySet()) {
            builder.set((CaptureRequest.Key) entry.getKey(), entry.getValue());
        }
    }

    public static CaptureRequest e(F f, CameraDevice cameraDevice, HashMap map, boolean z, androidx.camera.camera2.internal.compat.workaround.a aVar) throws CameraAccessException {
        CaptureRequest.Builder builderCreateCaptureRequest;
        InterfaceC0177p interfaceC0177p;
        if (cameraDevice == null) {
            return null;
        }
        List listUnmodifiableList = Collections.unmodifiableList(f.a);
        ArrayList arrayList = new ArrayList();
        Iterator it2 = listUnmodifiableList.iterator();
        while (it2.hasNext()) {
            Surface surface = (Surface) map.get((J) it2.next());
            if (surface == null) {
                throw new IllegalArgumentException("DeferrableSurface not in configuredSurfaceMap");
            }
            arrayList.add(surface);
        }
        if (arrayList.isEmpty()) {
            return null;
        }
        int i = f.c;
        if (i == 5 && (interfaceC0177p = f.g) != null && (interfaceC0177p.e() instanceof TotalCaptureResult)) {
            AbstractC3053s1.f(3, "Camera2CaptureRequestBuilder");
            builderCreateCaptureRequest = cameraDevice.createReprocessCaptureRequest((TotalCaptureResult) interfaceC0177p.e());
        } else {
            AbstractC3053s1.f(3, "Camera2CaptureRequestBuilder");
            if (i == 5) {
                builderCreateCaptureRequest = cameraDevice.createCaptureRequest(z ? 1 : 2);
            } else {
                builderCreateCaptureRequest = cameraDevice.createCaptureRequest(i);
            }
        }
        d(builderCreateCaptureRequest, i, aVar);
        C0162c c0162c = F.j;
        Object objE = C0168g.f;
        C0163c0 c0163c0 = f.b;
        try {
            objE = c0163c0.e(c0162c);
        } catch (IllegalArgumentException unused) {
        }
        Range range = (Range) objE;
        Objects.requireNonNull(range);
        Object objE2 = C0168g.f;
        if (!range.equals(objE2)) {
            CaptureRequest.Key key = CaptureRequest.CONTROL_AE_TARGET_FPS_RANGE;
            try {
                objE2 = c0163c0.e(F.j);
            } catch (IllegalArgumentException unused2) {
            }
            Range range2 = (Range) objE2;
            Objects.requireNonNull(range2);
            builderCreateCaptureRequest.set(key, range2);
        }
        if (f.a() == 1 || f.b() == 1) {
            builderCreateCaptureRequest.set(CaptureRequest.CONTROL_VIDEO_STABILIZATION_MODE, 0);
        } else if (f.a() == 2) {
            builderCreateCaptureRequest.set(CaptureRequest.CONTROL_VIDEO_STABILIZATION_MODE, 2);
        } else if (f.b() == 2) {
            builderCreateCaptureRequest.set(CaptureRequest.CONTROL_VIDEO_STABILIZATION_MODE, 1);
        }
        C0162c c0162c2 = F.h;
        TreeMap treeMap = c0163c0.a;
        if (treeMap.containsKey(c0162c2)) {
            builderCreateCaptureRequest.set(CaptureRequest.JPEG_ORIENTATION, (Integer) c0163c0.e(c0162c2));
        }
        C0162c c0162c3 = F.i;
        if (treeMap.containsKey(c0162c3)) {
            builderCreateCaptureRequest.set(CaptureRequest.JPEG_QUALITY, Byte.valueOf(((Integer) c0163c0.e(c0162c3)).byteValue()));
        }
        c(builderCreateCaptureRequest, c0163c0);
        Iterator it3 = arrayList.iterator();
        while (it3.hasNext()) {
            builderCreateCaptureRequest.addTarget((Surface) it3.next());
        }
        builderCreateCaptureRequest.setTag(f.f);
        return builderCreateCaptureRequest.build();
    }

    public static CaptureRequest f(F f, CameraDevice cameraDevice, androidx.camera.camera2.internal.compat.workaround.a aVar) throws CameraAccessException {
        if (cameraDevice == null) {
            return null;
        }
        AbstractC3053s1.f(3, "Camera2CaptureRequestBuilder");
        int i = f.c;
        CaptureRequest.Builder builderCreateCaptureRequest = cameraDevice.createCaptureRequest(i);
        d(builderCreateCaptureRequest, i, aVar);
        c(builderCreateCaptureRequest, f.b);
        return builderCreateCaptureRequest.build();
    }

    public static final com.google.common.collect.j g(List... lists) {
        com.google.common.collect.j jVarK;
        Intrinsics.checkNotNullParameter(lists, "lists");
        Iterable[] iterableArr = (Iterable[]) Arrays.copyOf(lists, lists.length);
        Iterable[] iterableArr2 = (Iterable[]) Arrays.copyOf(iterableArr, iterableArr.length);
        for (Iterable iterable : iterableArr2) {
            iterable.getClass();
        }
        Iterable nVar = new n(iterableArr2, 1);
        C3922e c3922e = com.google.common.collect.j.b;
        if (nVar instanceof Collection) {
            jVarK = com.google.common.collect.j.m((Collection) nVar);
        } else {
            s sVar = (s) nVar.iterator();
            if (sVar.hasNext()) {
                Object next = sVar.next();
                if (sVar.hasNext()) {
                    C3268u c3268u = new C3268u(2);
                    c3268u.a(next);
                    while (sVar.hasNext()) {
                        c3268u.a(sVar.next());
                    }
                    c3268u.c = true;
                    jVarK = com.google.common.collect.j.k(c3268u.b, c3268u.a);
                } else {
                    Object[] objArr = {next};
                    AbstractC3531s4.e(1, objArr);
                    jVarK = com.google.common.collect.j.k(1, objArr);
                }
            } else {
                jVarK = x.e;
            }
        }
        Intrinsics.checkNotNullExpressionValue(jVarK, "copyOf(...)");
        return jVarK;
    }
}

package androidx.camera.core.processing;

import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.opengl.EGL14;
import android.opengl.EGLConfig;
import android.opengl.EGLContext;
import android.opengl.EGLDisplay;
import android.opengl.EGLExt;
import android.opengl.EGLSurface;
import android.opengl.GLES20;
import android.os.Bundle;
import android.util.Size;
import android.view.Surface;
import androidx.camera.camera2.internal.s0;
import androidx.camera.core.C0196t;
import androidx.collection.C0222u;
import androidx.collection.C0223v;
import androidx.compose.animation.core.AbstractC0267t;
import androidx.compose.animation.core.B;
import androidx.compose.animation.core.C0271v;
import androidx.compose.animation.core.L0;
import androidx.compose.animation.core.M0;
import androidx.compose.animation.core.P0;
import androidx.compose.animation.core.T0;
import androidx.compose.animation.d0;
import androidx.webkit.internal.p;
import com.google.android.gms.ads.internal.client.r;
import com.google.android.gms.ads.internal.util.C;
import com.google.android.gms.ads.internal.util.client.VersionInfoParcel;
import com.google.android.gms.internal.ads.AbstractC2270kd;
import com.google.android.gms.internal.ads.AbstractC2330lu;
import com.google.android.gms.internal.ads.AbstractC2773w7;
import com.google.android.gms.internal.ads.C2023eq;
import com.google.android.gms.internal.ads.C2084g6;
import com.google.android.gms.internal.ads.C2227jd;
import com.google.android.gms.internal.ads.C2244ju;
import com.google.android.gms.internal.ads.CallableC2516q7;
import com.google.android.gms.internal.ads.InterfaceC2907zC;
import com.google.android.gms.internal.ads.Iq;
import com.google.android.gms.internal.ads.Iv;
import com.google.android.gms.internal.ads.Jq;
import com.google.android.gms.internal.ads.Jv;
import com.google.android.gms.internal.ads.Lq;
import com.google.android.gms.internal.ads.Ng;
import com.google.android.gms.internal.ads.Og;
import com.google.android.gms.internal.ads.Vh;
import com.google.android.gms.internal.ads.Xo;
import com.google.android.gms.internal.measurement.AbstractC3053s1;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3242q6;
import com.google.firebase.messaging.u;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public class e implements P0 {
    public int a;
    public Object b;
    public final Object c;
    public final Object d;
    public Object e;
    public Object f;
    public Object g;
    public Object h;
    public Object i;
    public Object j;
    public Object k;
    public Object l;
    public Object m;

    public e(Lq lq, VersionInfoParcel versionInfoParcel, ApplicationInfo applicationInfo, String str, ArrayList arrayList, PackageInfo packageInfo, InterfaceC2907zC interfaceC2907zC, C c, String str2, Xo xo, C2023eq c2023eq, Vh vh, int i) {
        this.c = lq;
        this.d = versionInfoParcel;
        this.e = applicationInfo;
        this.f = str;
        this.g = arrayList;
        this.b = packageInfo;
        this.h = interfaceC2907zC;
        this.i = str2;
        this.j = xo;
        this.k = c;
        this.l = c2023eq;
        this.m = vh;
        this.a = i;
    }

    public void c(C0196t c0196t, u uVar) {
        EGLDisplay eGLDisplayEglGetDisplay = EGL14.eglGetDisplay(0);
        this.f = eGLDisplayEglGetDisplay;
        if (Objects.equals(eGLDisplayEglGetDisplay, EGL14.EGL_NO_DISPLAY)) {
            throw new IllegalStateException("Unable to get EGL14 display");
        }
        int[] iArr = new int[2];
        if (!EGL14.eglInitialize((EGLDisplay) this.f, iArr, 0, iArr, 1)) {
            this.f = EGL14.EGL_NO_DISPLAY;
            throw new IllegalStateException("Unable to initialize EGL14");
        }
        if (uVar != null) {
            String str = iArr[0] + "." + iArr[1];
            if (str == null) {
                throw new NullPointerException("Null eglVersion");
            }
            uVar.b = str;
        }
        int i = c0196t.a() ? 10 : 8;
        EGLConfig[] eGLConfigArr = new EGLConfig[1];
        if (!EGL14.eglChooseConfig((EGLDisplay) this.f, new int[]{12324, i, 12323, i, 12322, i, 12321, c0196t.a() ? 2 : 8, 12325, 0, 12326, 0, 12352, c0196t.a() ? 64 : 4, 12610, c0196t.a() ? -1 : 1, 12339, 5, 12344}, 0, eGLConfigArr, 0, 1, new int[1], 0)) {
            throw new IllegalStateException("Unable to find a suitable EGLConfig");
        }
        EGLConfig eGLConfig = eGLConfigArr[0];
        EGLContext eGLContextEglCreateContext = EGL14.eglCreateContext((EGLDisplay) this.f, eGLConfig, EGL14.EGL_NO_CONTEXT, new int[]{12440, c0196t.a() ? 3 : 2, 12344}, 0);
        androidx.camera.core.processing.util.i.a("eglCreateContext");
        this.h = eGLConfig;
        this.g = eGLContextEglCreateContext;
        EGL14.eglQueryContext((EGLDisplay) this.f, eGLContextEglCreateContext, 12440, new int[1], 0);
    }

    public androidx.camera.core.processing.util.c d(Surface surface) {
        try {
            EGLDisplay eGLDisplay = (EGLDisplay) this.f;
            EGLConfig eGLConfig = (EGLConfig) this.h;
            Objects.requireNonNull(eGLConfig);
            EGLSurface eGLSurfaceI = androidx.camera.core.processing.util.i.i(eGLDisplay, eGLConfig, surface, (int[]) this.b);
            EGLDisplay eGLDisplay2 = (EGLDisplay) this.f;
            int[] iArr = new int[1];
            EGL14.eglQuerySurface(eGLDisplay2, eGLSurfaceI, 12375, iArr, 0);
            int i = iArr[0];
            int[] iArr2 = new int[1];
            EGL14.eglQuerySurface(eGLDisplay2, eGLSurfaceI, 12374, iArr2, 0);
            Size size = new Size(i, iArr2[0]);
            return new androidx.camera.core.processing.util.c(eGLSurfaceI, size.getWidth(), size.getHeight());
        } catch (IllegalArgumentException | IllegalStateException e) {
            AbstractC3053s1.i("OpenGlRenderer", "Failed to create EGL surface: " + e.getMessage(), e);
            return null;
        }
    }

    public void e() {
        EGLDisplay eGLDisplay = (EGLDisplay) this.f;
        EGLConfig eGLConfig = (EGLConfig) this.h;
        Objects.requireNonNull(eGLConfig);
        int[] iArr = androidx.camera.core.processing.util.i.a;
        EGLSurface eGLSurfaceEglCreatePbufferSurface = EGL14.eglCreatePbufferSurface(eGLDisplay, eGLConfig, new int[]{12375, 1, 12374, 1, 12344}, 0);
        androidx.camera.core.processing.util.i.a("eglCreatePbufferSurface");
        if (eGLSurfaceEglCreatePbufferSurface == null) {
            throw new IllegalStateException("surface was null");
        }
        this.i = eGLSurfaceEglCreatePbufferSurface;
    }

    public int f(int i) {
        int i2;
        C0222u c0222u = (C0222u) this.c;
        int i3 = c0222u.b;
        if (i3 < 0) {
            throw new IllegalArgumentException(d0.m(')', i3, "fromIndex(0) > toIndex("));
        }
        int i4 = i3 - 1;
        int i5 = 0;
        while (true) {
            if (i5 <= i4) {
                i2 = (i5 + i4) >>> 1;
                int iC = c0222u.c(i2);
                if (iC >= i) {
                    if (iC <= i) {
                        break;
                    }
                    i4 = i2 - 1;
                } else {
                    i5 = i2 + 1;
                }
            } else {
                i2 = -(i5 + 1);
                break;
            }
        }
        return i2 < -1 ? -(i2 + 2) : i2;
    }

    public float g(int i, int i2, boolean z) {
        B b;
        float f;
        C0222u c0222u = (C0222u) this.c;
        if (i >= c0222u.b - 1) {
            f = i2;
        } else {
            int iC = c0222u.c(i);
            int iC2 = c0222u.c(i + 1);
            if (i2 == iC) {
                f = iC;
            } else {
                int i3 = iC2 - iC;
                T0 t0 = (T0) ((C0223v) this.d).e(iC);
                if (t0 == null || (b = t0.b) == null) {
                    b = (s0) this.e;
                }
                float f2 = i3;
                float fB = b.b((i2 - iC) / f2);
                if (z) {
                    return fB;
                }
                f = (f2 * fB) + iC;
            }
        }
        return f / 1000;
    }

    public androidx.core.util.c h(C0196t c0196t) {
        androidx.camera.core.processing.util.i.d((AtomicBoolean) this.c, false);
        try {
            c(c0196t, null);
            e();
            l((EGLSurface) this.i);
            String strGlGetString = GLES20.glGetString(7939);
            String strEglQueryString = EGL14.eglQueryString((EGLDisplay) this.f, 12373);
            if (strGlGetString == null) {
                strGlGetString = "";
            }
            if (strEglQueryString == null) {
                strEglQueryString = "";
            }
            return new androidx.core.util.c(strGlGetString, strEglQueryString);
        } catch (IllegalStateException e) {
            AbstractC3053s1.i("OpenGlRenderer", "Failed to get GL or EGL extensions: " + e.getMessage(), e);
            return new androidx.core.util.c("", "");
        } finally {
            p();
        }
    }

    public androidx.camera.core.processing.util.a i(C0196t c0196t) {
        Map map = Collections.EMPTY_MAP;
        AtomicBoolean atomicBoolean = (AtomicBoolean) this.c;
        androidx.camera.core.processing.util.i.d(atomicBoolean, false);
        u uVar = new u();
        uVar.a = "0.0";
        uVar.b = "0.0";
        uVar.c = "";
        uVar.d = "";
        try {
            if (c0196t.a()) {
                androidx.core.util.c cVarH = h(c0196t);
                String str = (String) cVarH.a;
                str.getClass();
                String str2 = (String) cVarH.b;
                str2.getClass();
                if (!str.contains("GL_EXT_YUV_target")) {
                    AbstractC3053s1.h("OpenGlRenderer", "Device does not support GL_EXT_YUV_target. Fallback to SDR.");
                    c0196t = C0196t.d;
                }
                this.b = androidx.camera.core.processing.util.i.f(str2, c0196t);
                uVar.c = str;
                uVar.d = str2;
            }
            c(c0196t, uVar);
            e();
            l((EGLSurface) this.i);
            String strJ = androidx.camera.core.processing.util.i.j();
            if (strJ == null) {
                throw new NullPointerException("Null glVersion");
            }
            uVar.a = strJ;
            this.k = androidx.camera.core.processing.util.i.g(c0196t);
            int iH = androidx.camera.core.processing.util.i.h();
            this.a = iH;
            s(iH);
            this.e = Thread.currentThread();
            atomicBoolean.set(true);
            String strK = ((String) uVar.a) == null ? " glVersion" : "";
            if (((String) uVar.b) == null) {
                strK = strK.concat(" eglVersion");
            }
            if (((String) uVar.c) == null) {
                strK = android.support.v4.media.session.a.k(strK, " glExtensions");
            }
            if (((String) uVar.d) == null) {
                strK = android.support.v4.media.session.a.k(strK, " eglExtensions");
            }
            if (strK.isEmpty()) {
                return new androidx.camera.core.processing.util.a((String) uVar.a, (String) uVar.b, (String) uVar.c, (String) uVar.d);
            }
            throw new IllegalStateException("Missing required properties:".concat(strK));
        } catch (IllegalArgumentException e) {
            e = e;
            p();
            throw e;
        } catch (IllegalStateException e2) {
            e = e2;
            p();
            throw e;
        }
    }

    @Override // androidx.compose.animation.core.N0
    public AbstractC0267t j(long j, AbstractC0267t abstractC0267t, AbstractC0267t abstractC0267t2, AbstractC0267t abstractC0267t3) throws Throwable {
        int i = 0;
        long jD = kotlin.ranges.l.d((j / 1000000) - 0, 0L, this.a);
        if (jD < 0) {
            return abstractC0267t3;
        }
        k(abstractC0267t, abstractC0267t2, abstractC0267t3);
        if (((p) this.m) == null) {
            AbstractC0267t abstractC0267tT = t((jD - 1) * 1000000, abstractC0267t, abstractC0267t2, abstractC0267t3);
            AbstractC0267t abstractC0267tT2 = t(jD * 1000000, abstractC0267t, abstractC0267t2, abstractC0267t3);
            int iB = abstractC0267tT.b();
            while (i < iB) {
                AbstractC0267t abstractC0267t4 = (AbstractC0267t) this.h;
                if (abstractC0267t4 == null) {
                    Intrinsics.m("velocityVector");
                    throw null;
                }
                abstractC0267t4.e((abstractC0267tT.a(i) - abstractC0267tT2.a(i)) * 1000.0f, i);
                i++;
            }
            AbstractC0267t abstractC0267t5 = (AbstractC0267t) this.h;
            if (abstractC0267t5 != null) {
                return abstractC0267t5;
            }
            Intrinsics.m("velocityVector");
            throw null;
        }
        int i2 = (int) jD;
        float fG = g(f(i2), i2, false);
        p pVar = (p) this.m;
        if (pVar == null) {
            Intrinsics.m("arcSpline");
            throw null;
        }
        float[] fArr = (float[]) this.l;
        if (fArr == null) {
            Intrinsics.m("slopeArray");
            throw null;
        }
        C0271v[][] c0271vArr = (C0271v[][]) pVar.b;
        float f = c0271vArr[0][0].a;
        if (fG < f) {
            fG = f;
        } else if (fG > c0271vArr[c0271vArr.length - 1][0].b) {
            fG = c0271vArr[c0271vArr.length - 1][0].b;
        }
        int length = c0271vArr.length;
        boolean z = false;
        for (int i3 = 0; i3 < length; i3++) {
            int i4 = 0;
            int i5 = 0;
            while (i4 < fArr.length) {
                C0271v c0271v = c0271vArr[i3][i5];
                if (fG <= c0271v.b) {
                    if (c0271v.r) {
                        fArr[i4] = c0271v.n;
                        fArr[i4 + 1] = c0271v.o;
                    } else {
                        c0271v.c(fG);
                        fArr[i4] = c0271vArr[i3][i5].a();
                        fArr[i4 + 1] = c0271vArr[i3][i5].b();
                    }
                    z = true;
                }
                i4 += 2;
                i5++;
            }
            if (z) {
                break;
            }
        }
        float[] fArr2 = (float[]) this.l;
        if (fArr2 == null) {
            Intrinsics.m("slopeArray");
            throw null;
        }
        int length2 = fArr2.length;
        while (i < length2) {
            AbstractC0267t abstractC0267t6 = (AbstractC0267t) this.h;
            if (abstractC0267t6 == null) {
                Intrinsics.m("velocityVector");
                throw null;
            }
            float[] fArr3 = (float[]) this.l;
            if (fArr3 == null) {
                Intrinsics.m("slopeArray");
                throw null;
            }
            abstractC0267t6.e(fArr3[i], i);
            i++;
        }
        AbstractC0267t abstractC0267t7 = (AbstractC0267t) this.h;
        if (abstractC0267t7 != null) {
            return abstractC0267t7;
        }
        Intrinsics.m("velocityVector");
        throw null;
    }

    public void k(AbstractC0267t abstractC0267t, AbstractC0267t abstractC0267t2, AbstractC0267t abstractC0267t3) {
        float[] fArr;
        float[] fArr2;
        boolean z = ((p) this.m) != null;
        AbstractC0267t abstractC0267t4 = (AbstractC0267t) this.g;
        C0223v c0223v = (C0223v) this.d;
        C0222u c0222u = (C0222u) this.c;
        if (abstractC0267t4 == null) {
            this.g = abstractC0267t.c();
            this.h = abstractC0267t3.c();
            int i = c0222u.b;
            float[] fArr3 = new float[i];
            for (int i2 = 0; i2 < i; i2++) {
                fArr3[i2] = c0222u.c(i2) / 1000;
            }
            this.f = fArr3;
            int i3 = c0222u.b;
            int[] iArr = new int[i3];
            for (int i4 = 0; i4 < i3; i4++) {
                iArr[i4] = 0;
            }
            this.b = iArr;
        }
        if (z) {
            if (((p) this.m) != null) {
                AbstractC0267t abstractC0267t5 = (AbstractC0267t) this.i;
                if (abstractC0267t5 == null) {
                    Intrinsics.m("lastInitialValue");
                    throw null;
                }
                if (abstractC0267t5.equals(abstractC0267t)) {
                    AbstractC0267t abstractC0267t6 = (AbstractC0267t) this.j;
                    if (abstractC0267t6 == null) {
                        Intrinsics.m("lastTargetValue");
                        throw null;
                    }
                    if (abstractC0267t6.equals(abstractC0267t2)) {
                        return;
                    }
                }
            }
            this.i = abstractC0267t;
            this.j = abstractC0267t2;
            int iB = abstractC0267t.b() + (abstractC0267t.b() % 2);
            this.k = new float[iB];
            this.l = new float[iB];
            int i5 = c0222u.b;
            float[][] fArr4 = new float[i5][];
            for (int i6 = 0; i6 < i5; i6++) {
                int iC = c0222u.c(i6);
                if (iC != 0) {
                    if (iC != this.a) {
                        fArr = new float[iB];
                        Object objE = c0223v.e(iC);
                        Intrinsics.d(objE);
                        T0 t0 = (T0) objE;
                        for (int i7 = 0; i7 < iB; i7++) {
                            fArr[i7] = t0.a.a(i7);
                        }
                    } else if (c0223v.b(iC)) {
                        fArr = new float[iB];
                        Object objE2 = c0223v.e(iC);
                        Intrinsics.d(objE2);
                        T0 t02 = (T0) objE2;
                        for (int i8 = 0; i8 < iB; i8++) {
                            fArr[i8] = t02.a.a(i8);
                        }
                    } else {
                        fArr2 = new float[iB];
                        for (int i9 = 0; i9 < iB; i9++) {
                            fArr2[i9] = abstractC0267t2.a(i9);
                        }
                    }
                    fArr2 = fArr;
                } else if (c0223v.b(iC)) {
                    fArr = new float[iB];
                    Object objE3 = c0223v.e(iC);
                    Intrinsics.d(objE3);
                    T0 t03 = (T0) objE3;
                    for (int i10 = 0; i10 < iB; i10++) {
                        fArr[i10] = t03.a.a(i10);
                    }
                    fArr2 = fArr;
                } else {
                    fArr2 = new float[iB];
                    for (int i11 = 0; i11 < iB; i11++) {
                        fArr2[i11] = abstractC0267t.a(i11);
                    }
                }
                fArr4[i6] = fArr2;
            }
            int[] iArr2 = (int[]) this.b;
            if (iArr2 == null) {
                Intrinsics.m("modes");
                throw null;
            }
            float[] fArr5 = (float[]) this.f;
            if (fArr5 == null) {
                Intrinsics.m("times");
                throw null;
            }
            this.m = new p(iArr2, fArr5, fArr4);
        }
    }

    public void l(EGLSurface eGLSurface) {
        ((EGLDisplay) this.f).getClass();
        ((EGLContext) this.g).getClass();
        if (!EGL14.eglMakeCurrent((EGLDisplay) this.f, eGLSurface, eGLSurface, (EGLContext) this.g)) {
            throw new IllegalStateException("eglMakeCurrent failed");
        }
    }

    @Override // androidx.compose.animation.core.P0
    public int m() {
        return 0;
    }

    public void o(Surface surface) {
        androidx.camera.core.processing.util.i.d((AtomicBoolean) this.c, true);
        androidx.camera.core.processing.util.i.c((Thread) this.e);
        HashMap map = (HashMap) this.d;
        if (map.containsKey(surface)) {
            return;
        }
        map.put(surface, androidx.camera.core.processing.util.i.j);
    }

    public void p() {
        Iterator it2 = ((Map) this.k).values().iterator();
        while (it2.hasNext()) {
            GLES20.glDeleteProgram(((androidx.camera.core.processing.util.g) it2.next()).a);
        }
        this.k = Collections.EMPTY_MAP;
        this.l = null;
        if (!Objects.equals((EGLDisplay) this.f, EGL14.EGL_NO_DISPLAY)) {
            EGLDisplay eGLDisplay = (EGLDisplay) this.f;
            EGLSurface eGLSurface = EGL14.EGL_NO_SURFACE;
            EGL14.eglMakeCurrent(eGLDisplay, eGLSurface, eGLSurface, EGL14.EGL_NO_CONTEXT);
            HashMap map = (HashMap) this.d;
            for (androidx.camera.core.processing.util.c cVar : map.values()) {
                if (!Objects.equals(cVar.a, EGL14.EGL_NO_SURFACE) && !EGL14.eglDestroySurface((EGLDisplay) this.f, cVar.a)) {
                    try {
                        androidx.camera.core.processing.util.i.a("eglDestroySurface");
                    } catch (IllegalStateException e) {
                        AbstractC3053s1.d("GLUtils", e.toString(), e);
                    }
                }
            }
            map.clear();
            if (!Objects.equals((EGLSurface) this.i, EGL14.EGL_NO_SURFACE)) {
                EGL14.eglDestroySurface((EGLDisplay) this.f, (EGLSurface) this.i);
                this.i = EGL14.EGL_NO_SURFACE;
            }
            if (!Objects.equals((EGLContext) this.g, EGL14.EGL_NO_CONTEXT)) {
                EGL14.eglDestroyContext((EGLDisplay) this.f, (EGLContext) this.g);
                this.g = EGL14.EGL_NO_CONTEXT;
            }
            EGL14.eglReleaseThread();
            EGL14.eglTerminate((EGLDisplay) this.f);
            this.f = EGL14.EGL_NO_DISPLAY;
        }
        this.h = null;
        this.a = -1;
        this.m = androidx.camera.core.processing.util.f.a;
        this.j = null;
        this.e = null;
    }

    public void q(Surface surface, boolean z) {
        if (((Surface) this.j) == surface) {
            this.j = null;
            l((EGLSurface) this.i);
        }
        HashMap map = (HashMap) this.d;
        androidx.camera.core.processing.util.c cVar = z ? (androidx.camera.core.processing.util.c) map.remove(surface) : (androidx.camera.core.processing.util.c) map.put(surface, androidx.camera.core.processing.util.i.j);
        if (cVar == null || cVar == androidx.camera.core.processing.util.i.j) {
            return;
        }
        try {
            EGL14.eglDestroySurface((EGLDisplay) this.f, cVar.a);
        } catch (RuntimeException e) {
            AbstractC3053s1.i("OpenGlRenderer", "Failed to destroy EGL surface: " + e.getMessage(), e);
        }
    }

    public void r(long j, float[] fArr, Surface surface) {
        androidx.camera.core.processing.util.i.d((AtomicBoolean) this.c, true);
        androidx.camera.core.processing.util.i.c((Thread) this.e);
        HashMap map = (HashMap) this.d;
        AbstractC3242q6.h("The surface is not registered.", map.containsKey(surface));
        androidx.camera.core.processing.util.c cVarD = (androidx.camera.core.processing.util.c) map.get(surface);
        Objects.requireNonNull(cVarD);
        if (cVarD == androidx.camera.core.processing.util.i.j) {
            cVarD = d(surface);
            if (cVarD == null) {
                return;
            } else {
                map.put(surface, cVarD);
            }
        }
        Surface surface2 = (Surface) this.j;
        EGLSurface eGLSurface = cVarD.a;
        if (surface != surface2) {
            l(eGLSurface);
            this.j = surface;
            int i = cVarD.b;
            int i2 = cVarD.c;
            GLES20.glViewport(0, 0, i, i2);
            GLES20.glScissor(0, 0, i, i2);
        }
        androidx.camera.core.processing.util.g gVar = (androidx.camera.core.processing.util.g) this.l;
        gVar.getClass();
        if (gVar instanceof androidx.camera.core.processing.util.h) {
            GLES20.glUniformMatrix4fv(((androidx.camera.core.processing.util.h) gVar).f, 1, false, fArr, 0);
            androidx.camera.core.processing.util.i.b("glUniformMatrix4fv");
        }
        GLES20.glDrawArrays(5, 0, 4);
        androidx.camera.core.processing.util.i.b("glDrawArrays");
        EGLExt.eglPresentationTimeANDROID((EGLDisplay) this.f, eGLSurface, j);
        if (EGL14.eglSwapBuffers((EGLDisplay) this.f, eGLSurface)) {
            return;
        }
        AbstractC3053s1.h("OpenGlRenderer", "Failed to swap buffers with EGL error: 0x" + Integer.toHexString(EGL14.eglGetError()));
        q(surface, false);
    }

    public void s(int i) {
        androidx.camera.core.processing.util.g gVar = (androidx.camera.core.processing.util.g) ((Map) this.k).get((androidx.camera.core.processing.util.f) this.m);
        if (gVar == null) {
            throw new IllegalStateException("Unable to configure program for input format: " + ((androidx.camera.core.processing.util.f) this.m));
        }
        if (((androidx.camera.core.processing.util.g) this.l) != gVar) {
            this.l = gVar;
            gVar.b();
            Objects.toString((androidx.camera.core.processing.util.f) this.m);
            Objects.toString((androidx.camera.core.processing.util.g) this.l);
        }
        GLES20.glActiveTexture(33984);
        androidx.camera.core.processing.util.i.b("glActiveTexture");
        GLES20.glBindTexture(36197, i);
        androidx.camera.core.processing.util.i.b("glBindTexture");
    }

    @Override // androidx.compose.animation.core.N0
    public AbstractC0267t t(long j, AbstractC0267t abstractC0267t, AbstractC0267t abstractC0267t2, AbstractC0267t abstractC0267t3) throws Throwable {
        int i;
        Throwable th;
        int length;
        boolean z;
        int i2;
        AbstractC0267t abstractC0267t4 = abstractC0267t;
        AbstractC0267t abstractC0267t5 = abstractC0267t2;
        boolean z2 = true;
        int i3 = 0;
        int i4 = this.a;
        int iD = (int) kotlin.ranges.l.d((j / 1000000) - 0, 0L, i4);
        C0223v c0223v = (C0223v) this.d;
        if (c0223v.b(iD)) {
            Object objE = c0223v.e(iD);
            Intrinsics.d(objE);
            return ((T0) objE).a;
        }
        if (iD >= i4) {
            return abstractC0267t5;
        }
        if (iD <= 0) {
            return abstractC0267t4;
        }
        k(abstractC0267t4, abstractC0267t5, abstractC0267t3);
        if (((p) this.m) == null) {
            int iF = f(iD);
            float fG = g(iF, iD, true);
            C0222u c0222u = (C0222u) this.c;
            int iC = c0222u.c(iF);
            if (c0223v.b(iC)) {
                Object objE2 = c0223v.e(iC);
                Intrinsics.d(objE2);
                abstractC0267t4 = ((T0) objE2).a;
            }
            int iC2 = c0222u.c(iF + 1);
            if (c0223v.b(iC2)) {
                Object objE3 = c0223v.e(iC2);
                Intrinsics.d(objE3);
                abstractC0267t5 = ((T0) objE3).a;
            }
            AbstractC0267t abstractC0267t6 = (AbstractC0267t) this.g;
            if (abstractC0267t6 == null) {
                Intrinsics.m("valueVector");
                throw null;
            }
            int iB = abstractC0267t6.b();
            for (int i5 = 0; i5 < iB; i5++) {
                AbstractC0267t abstractC0267t7 = (AbstractC0267t) this.g;
                if (abstractC0267t7 == null) {
                    Intrinsics.m("valueVector");
                    throw null;
                }
                float fA = abstractC0267t4.a(i5);
                float fA2 = abstractC0267t5.a(i5);
                L0 l0 = M0.a;
                abstractC0267t7.e((fA2 * fG) + ((1 - fG) * fA), i5);
            }
            AbstractC0267t abstractC0267t8 = (AbstractC0267t) this.g;
            if (abstractC0267t8 != null) {
                return abstractC0267t8;
            }
            Intrinsics.m("valueVector");
            throw null;
        }
        float fG2 = g(f(iD), iD, false);
        p pVar = (p) this.m;
        if (pVar == null) {
            Intrinsics.m("arcSpline");
            throw null;
        }
        float[] fArr = (float[]) this.k;
        if (fArr == null) {
            Intrinsics.m("posArray");
            throw null;
        }
        C0271v[][] c0271vArr = (C0271v[][]) pVar.b;
        float f = c0271vArr[0][0].a;
        if (fG2 >= f && fG2 <= c0271vArr[c0271vArr.length - 1][0].b) {
            int length2 = c0271vArr.length;
            int i6 = 0;
            boolean z3 = false;
            while (true) {
                if (i6 >= length2) {
                    i = i3;
                    th = null;
                    break;
                }
                int i7 = i3;
                int i8 = i7;
                while (i7 < fArr.length) {
                    C0271v c0271v = c0271vArr[i6][i8];
                    if (fG2 <= c0271v.b) {
                        if (c0271v.r) {
                            float f2 = c0271v.a;
                            i2 = i3;
                            float f3 = c0271v.k;
                            float f4 = c0271v.e;
                            z = z2;
                            float f5 = c0271v.c;
                            fArr[i7] = android.support.v4.media.session.a.a(f4, f5, (fG2 - f2) * f3, f5);
                            float f6 = (fG2 - f2) * f3;
                            float f7 = c0271v.f;
                            float f8 = c0271v.d;
                            fArr[i7 + 1] = android.support.v4.media.session.a.a(f7, f8, f6, f8);
                        } else {
                            z = z2;
                            i2 = i3;
                            c0271v.c(fG2);
                            C0271v c0271v2 = c0271vArr[i6][i8];
                            fArr[i7] = (c0271v2.l * c0271v2.h) + c0271v2.n;
                            fArr[i7 + 1] = (c0271v2.m * c0271v2.i) + c0271v2.o;
                        }
                        z3 = z;
                    } else {
                        z = z2;
                        i2 = i3;
                    }
                    i7 += 2;
                    i8++;
                    i3 = i2;
                    z2 = z;
                }
                boolean z4 = z2;
                i = i3;
                th = null;
                if (z3) {
                    break;
                }
                i6++;
                i3 = i;
                z2 = z4;
            }
        } else {
            i = 0;
            th = null;
            if (fG2 > c0271vArr[c0271vArr.length - 1][0].b) {
                length = c0271vArr.length - 1;
                f = c0271vArr[c0271vArr.length - 1][0].b;
            } else {
                length = 0;
            }
            float f9 = fG2 - f;
            int i9 = 0;
            int i10 = 0;
            while (i9 < fArr.length) {
                C0271v c0271v3 = c0271vArr[length][i10];
                if (c0271v3.r) {
                    float f10 = c0271v3.a;
                    float f11 = c0271v3.k;
                    float f12 = c0271v3.e;
                    float f13 = c0271v3.c;
                    fArr[i9] = (c0271v3.n * f9) + android.support.v4.media.session.a.a(f12, f13, (f - f10) * f11, f13);
                    float f14 = (f - f10) * f11;
                    float f15 = c0271v3.f;
                    float f16 = c0271v3.d;
                    fArr[i9 + 1] = (c0271v3.o * f9) + android.support.v4.media.session.a.a(f15, f16, f14, f16);
                } else {
                    c0271v3.c(f);
                    C0271v c0271v4 = c0271vArr[length][i10];
                    fArr[i9] = (c0271v4.a() * f9) + (c0271v4.l * c0271v4.h) + c0271v4.n;
                    C0271v c0271v5 = c0271vArr[length][i10];
                    fArr[i9 + 1] = (c0271v5.b() * f9) + (c0271v5.m * c0271v5.i) + c0271v5.o;
                }
                i9 += 2;
                i10++;
            }
        }
        float[] fArr2 = (float[]) this.k;
        if (fArr2 == null) {
            Intrinsics.m("posArray");
            throw th;
        }
        int length3 = fArr2.length;
        for (int i11 = i; i11 < length3; i11++) {
            AbstractC0267t abstractC0267t9 = (AbstractC0267t) this.g;
            if (abstractC0267t9 == null) {
                Intrinsics.m("valueVector");
                throw th;
            }
            float[] fArr3 = (float[]) this.k;
            if (fArr3 == null) {
                Intrinsics.m("posArray");
                throw th;
            }
            abstractC0267t9.e(fArr3[i11], i11);
        }
        AbstractC0267t abstractC0267t10 = (AbstractC0267t) this.g;
        if (abstractC0267t10 != null) {
            return abstractC0267t10;
        }
        Intrinsics.m("valueVector");
        throw th;
    }

    @Override // androidx.compose.animation.core.P0
    public int u() {
        return this.a;
    }

    public Iq v(Bundle bundle) {
        ((Vh) this.m).a();
        return new C2084g6((Lq) this.c, Jq.SIGNALS, null, Lq.d, Collections.EMPTY_LIST, ((Xo) this.j).a(new Og(new Bundle(), new Bundle()), bundle, this.a == 2)).b();
    }

    public Iq w() {
        Bundle bundle = new Bundle();
        if (((Boolean) r.d.c.a(AbstractC2773w7.h2)).booleanValue()) {
            Bundle bundle2 = ((C2023eq) this.l).s;
            if (bundle2 != null) {
                bundle.putAll(bundle2);
            }
            bundle.putBoolean("ls", false);
        }
        Iq iqV = v(bundle);
        Jq jq = Jq.REQUEST_PARCEL;
        com.google.common.util.concurrent.e[] eVarArr = {iqV, (com.google.common.util.concurrent.e) ((InterfaceC2907zC) this.h).zzb()};
        Lq lq = (Lq) this.c;
        lq.getClass();
        List listAsList = Arrays.asList(eVarArr);
        Ng ng = new Ng(this, iqV, bundle);
        C2244ju c2244ju = AbstractC2330lu.b;
        listAsList.getClass();
        AbstractC2330lu abstractC2330luN = AbstractC2330lu.n(listAsList);
        CallableC2516q7 callableC2516q7 = new CallableC2516q7(6);
        C2227jd c2227jd = AbstractC2270kd.g;
        Jv jv = new Jv(abstractC2330luN, true, false);
        jv.p = new Iv(jv, callableC2516q7, c2227jd);
        jv.z();
        Jv jv2 = new Jv(abstractC2330luN, true, false);
        jv2.p = new Iv(jv2, ng, lq.a);
        jv2.z();
        return new C2084g6(lq, jq, null, jv, listAsList, jv2).b();
    }

    public e() {
        this.c = new AtomicBoolean(false);
        this.d = new HashMap();
        this.f = EGL14.EGL_NO_DISPLAY;
        this.g = EGL14.EGL_NO_CONTEXT;
        this.b = androidx.camera.core.processing.util.i.a;
        this.i = EGL14.EGL_NO_SURFACE;
        this.k = Collections.EMPTY_MAP;
        this.l = null;
        this.m = androidx.camera.core.processing.util.f.a;
        this.a = -1;
    }

    public e(C0222u c0222u, C0223v c0223v, int i, s0 s0Var) {
        this.c = c0222u;
        this.d = c0223v;
        this.a = i;
        this.e = s0Var;
    }
}

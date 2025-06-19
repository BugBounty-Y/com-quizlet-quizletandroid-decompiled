package androidx.camera.core.impl;

import androidx.camera.core.InterfaceC0188k;
import com.google.android.gms.internal.measurement.AbstractC3053s1;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3242q6;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3359k2;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

/* loaded from: classes.dex */
public final class D {
    public final StringBuilder a = new StringBuilder();
    public final Object b;
    public int c;
    public final androidx.camera.camera2.internal.concurrent.a d;
    public final HashMap e;
    public int f;

    public D(androidx.camera.camera2.internal.concurrent.a aVar) {
        Object obj = new Object();
        this.b = obj;
        this.e = new HashMap();
        this.c = 1;
        synchronized (obj) {
            this.d = aVar;
            this.f = this.c;
        }
    }

    public static void c(androidx.camera.camera2.internal.C c, EnumC0184x enumC0184x) {
        if (AbstractC3359k2.d()) {
            AbstractC3359k2.e(enumC0184x.ordinal(), "CX:State[" + c + "]");
        }
    }

    public final C a(String str) {
        HashMap map = this.e;
        for (InterfaceC0188k interfaceC0188k : map.keySet()) {
            if (str.equals(interfaceC0188k.a().c())) {
                return (C) map.get(interfaceC0188k);
            }
        }
        return null;
    }

    public final void b() {
        boolean zF = AbstractC3053s1.f(3, "CameraStateRegistry");
        StringBuilder sb = this.a;
        if (zF) {
            sb.setLength(0);
            sb.append("Recalculating open cameras:\n");
            sb.append(String.format(Locale.US, "%-45s%-22s\n", "Camera", "State"));
            sb.append("-------------------------------------------------------------------\n");
        }
        int i = 0;
        for (Map.Entry entry : this.e.entrySet()) {
            if (AbstractC3053s1.f(3, "CameraStateRegistry")) {
                sb.append(String.format(Locale.US, "%-45s%-22s\n", ((InterfaceC0188k) entry.getKey()).toString(), ((C) entry.getValue()).a != null ? ((C) entry.getValue()).a.toString() : "UNKNOWN"));
            }
            EnumC0184x enumC0184x = ((C) entry.getValue()).a;
            if (enumC0184x != null && enumC0184x.a) {
                i++;
            }
        }
        if (AbstractC3053s1.f(3, "CameraStateRegistry")) {
            sb.append("-------------------------------------------------------------------\n");
            Locale locale = Locale.US;
            sb.append(android.support.v4.media.session.a.j("Open count: ", i, " (Max allowed: ", ")", this.c));
            AbstractC3053s1.f(3, "CameraStateRegistry");
        }
        this.f = Math.max(this.c - i, 0);
    }

    public final boolean d(androidx.camera.camera2.internal.C c) {
        boolean z;
        synchronized (this.b) {
            try {
                C c2 = (C) this.e.get(c);
                AbstractC3242q6.g(c2, "Camera must first be registered with registerCamera()");
                z = true;
                if (AbstractC3053s1.f(3, "CameraStateRegistry")) {
                    this.a.setLength(0);
                    StringBuilder sb = this.a;
                    Locale locale = Locale.US;
                    int i = this.f;
                    EnumC0184x enumC0184x = c2.a;
                    boolean z2 = enumC0184x != null && enumC0184x.a;
                    sb.append("tryOpenCamera(" + c + ") [Available Cameras: " + i + ", Already Open: " + z2 + " (Previous state: " + c2.a + ")]");
                }
                if (this.f > 0) {
                    EnumC0184x enumC0184x2 = EnumC0184x.OPENING;
                    c2.a = enumC0184x2;
                    c(c, enumC0184x2);
                } else {
                    EnumC0184x enumC0184x3 = c2.a;
                    if (enumC0184x3 != null && enumC0184x3.a) {
                        EnumC0184x enumC0184x22 = EnumC0184x.OPENING;
                        c2.a = enumC0184x22;
                        c(c, enumC0184x22);
                    } else {
                        z = false;
                    }
                }
                if (AbstractC3053s1.f(3, "CameraStateRegistry")) {
                    StringBuilder sb2 = this.a;
                    Locale locale2 = Locale.US;
                    sb2.append(" --> ".concat(z ? "SUCCESS" : "FAIL"));
                    AbstractC3053s1.f(3, "CameraStateRegistry");
                }
                if (z) {
                    b();
                }
            } catch (Throwable th) {
                throw th;
            }
        }
        return z;
    }

    public final boolean e(String str, String str2) {
        synchronized (this.b) {
            try {
                boolean z = true;
                if (this.d.b != 2) {
                    return true;
                }
                C cA = a(str);
                EnumC0184x enumC0184x = cA != null ? cA.a : null;
                C cA2 = str2 != null ? a(str2) : null;
                EnumC0184x enumC0184x2 = cA2 != null ? cA2.a : null;
                EnumC0184x enumC0184x3 = EnumC0184x.OPEN;
                boolean z2 = enumC0184x3.equals(enumC0184x) || EnumC0184x.CONFIGURED.equals(enumC0184x);
                boolean z3 = enumC0184x3.equals(enumC0184x2) || EnumC0184x.CONFIGURED.equals(enumC0184x2);
                if (!z2 || !z3) {
                    z = false;
                }
                return z;
            } finally {
            }
        }
    }
}

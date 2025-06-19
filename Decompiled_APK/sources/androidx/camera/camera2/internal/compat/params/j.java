package androidx.camera.camera2.internal.compat.params;

import android.hardware.camera2.params.OutputConfiguration;
import android.view.Surface;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3242q6;
import java.util.Objects;

/* loaded from: classes.dex */
public class j {
    public final Object a;

    public j(Object obj) {
        this.a = obj;
    }

    public Object a() {
        Object obj = this.a;
        AbstractC3242q6.d(obj instanceof i);
        return ((i) obj).a;
    }

    public String b() {
        return ((i) this.a).b;
    }

    public final Surface c() {
        return ((OutputConfiguration) a()).getSurface();
    }

    public void d(long j) {
        ((i) this.a).c = j;
    }

    public void e(int i) {
    }

    public final boolean equals(Object obj) {
        if (!(obj instanceof j)) {
            return false;
        }
        return Objects.equals(this.a, ((j) obj).a);
    }

    public void f(String str) {
        ((i) this.a).b = str;
    }

    public void g(long j) {
    }

    public final int hashCode() {
        return this.a.hashCode();
    }
}

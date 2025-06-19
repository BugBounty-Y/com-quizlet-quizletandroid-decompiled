package androidx.camera.core.internal;

import androidx.camera.core.J;
import com.google.android.gms.internal.measurement.AbstractC3053s1;
import kotlin.Unit;

/* loaded from: classes.dex */
public final class i implements J {
    public final J a;
    public final Object b = new Object();
    public boolean c;

    public i(J j) {
        this.a = j;
    }

    public final void a() {
        Unit unit;
        synchronized (this.b) {
            try {
                if (this.c) {
                    J j = this.a;
                    if (j != null) {
                        j.clear();
                        unit = Unit.a;
                    } else {
                        unit = null;
                    }
                    if (unit == null) {
                        AbstractC3053s1.c("ScreenFlashWrapper", "completePendingScreenFlashClear: screenFlash is null!");
                    }
                } else {
                    AbstractC3053s1.h("ScreenFlashWrapper", "completePendingScreenFlashClear: none pending!");
                }
                this.c = false;
                Unit unit2 = Unit.a;
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public final void b() {
        synchronized (this.b) {
            Unit unit = Unit.a;
        }
    }

    @Override // androidx.camera.core.J
    public final void clear() {
        a();
    }
}

package androidx.camera.camera2.internal;

import android.hardware.camera2.CameraCharacteristics;
import androidx.camera.camera2.internal.compat.quirk.ZslDisablerQuirk;
import com.google.android.gms.auth.api.signin.GoogleSignInOptions;
import java.util.HashMap;
import java.util.HashSet;

/* loaded from: classes.dex */
public final class t0 {
    public boolean a;
    public final boolean b;
    public final boolean c;
    public final Object d;
    public final Object e;
    public Object f;
    public Object g;
    public Object h;
    public Object i;

    public t0() {
        this.d = new HashSet();
        this.h = new HashMap();
    }

    public t0(GoogleSignInOptions googleSignInOptions) {
        this.d = new HashSet();
        this.h = new HashMap();
        com.google.android.gms.common.internal.u.h(googleSignInOptions);
        this.d = new HashSet(googleSignInOptions.b);
        this.a = googleSignInOptions.e;
        this.b = googleSignInOptions.f;
        this.c = googleSignInOptions.d;
        this.e = googleSignInOptions.g;
        this.f = googleSignInOptions.c;
        this.g = googleSignInOptions.h;
        this.h = GoogleSignInOptions.b(googleSignInOptions.i);
        this.i = googleSignInOptions.j;
    }

    public t0(androidx.camera.camera2.internal.compat.k kVar) {
        boolean z;
        this.a = false;
        this.b = false;
        this.c = false;
        this.d = kVar;
        int[] iArr = (int[]) kVar.a(CameraCharacteristics.REQUEST_AVAILABLE_CAPABILITIES);
        if (iArr != null) {
            for (int i : iArr) {
                if (i == 4) {
                    z = true;
                    break;
                }
            }
            z = false;
        } else {
            z = false;
        }
        this.b = z;
        this.c = androidx.camera.camera2.internal.compat.quirk.b.a.b(ZslDisablerQuirk.class) != null;
        this.e = new com.quizlet.data.repository.user.a(new s0(0));
    }
}

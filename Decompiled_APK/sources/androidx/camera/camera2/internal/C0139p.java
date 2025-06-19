package androidx.camera.camera2.internal;

import androidx.camera.camera2.internal.compat.CameraAccessExceptionCompat;
import java.util.ArrayList;
import java.util.concurrent.RejectedExecutionException;

/* renamed from: androidx.camera.camera2.internal.p, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final /* synthetic */ class C0139p implements androidx.concurrent.futures.j {
    public final /* synthetic */ int a;
    public final /* synthetic */ C b;

    public /* synthetic */ C0139p(C c, int i) {
        this.a = i;
        this.b = c;
    }

    @Override // androidx.concurrent.futures.j
    public Object d(androidx.concurrent.futures.i iVar) {
        switch (this.a) {
            case 0:
                C c = this.b;
                c.getClass();
                try {
                    ArrayList arrayList = new ArrayList(c.a.a().b().c);
                    arrayList.add((N) c.x.g);
                    arrayList.add(new C0144v(c, iVar));
                    c.b.a.n(c.i.a, c.c, com.facebook.appevents.iap.u.c(arrayList));
                    return "configAndCloseTask";
                } catch (CameraAccessExceptionCompat | SecurityException e) {
                    c.t("Unable to open camera for configAndClose: " + e.getMessage());
                    iVar.d(e);
                    return "configAndCloseTask";
                }
            default:
                C c2 = this.b;
                c2.getClass();
                try {
                    c2.c.execute(new androidx.activity.r(7, c2, iVar));
                    return "isMeteringRepeatingAttached";
                } catch (RejectedExecutionException unused) {
                    iVar.d(new RuntimeException("Unable to check if MeteringRepeating is attached. Camera executor shut down."));
                    return "isMeteringRepeatingAttached";
                }
        }
    }
}

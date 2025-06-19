package dagger.hilt.android.internal.managers;

import android.app.Application;
import android.app.Service;
import com.google.android.gms.internal.mlkit_vision_barcode.K6;
import com.google.android.gms.internal.mlkit_vision_barcode.R6;
import com.quizlet.quizletandroid.o;
import com.quizlet.quizletandroid.u;

/* loaded from: classes3.dex */
public final class i implements dagger.hilt.internal.b {
    public final Service a;
    public o b;

    public i(Service service) {
        this.a = service;
    }

    @Override // dagger.hilt.internal.b
    public final Object d() {
        if (this.b == null) {
            Application application = this.a.getApplication();
            R6.b(application instanceof dagger.hilt.internal.b, "Hilt service must be attached to an @HiltAndroidApp Application. Found: %s", application.getClass());
            this.b = new o(((u) ((h) K6.b(h.class, application))).n);
        }
        return this.b;
    }
}
